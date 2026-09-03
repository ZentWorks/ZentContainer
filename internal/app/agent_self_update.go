package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ZentWorks/ZentContainer/internal/dockerx"
	"github.com/ZentWorks/ZentContainer/internal/store"
	"github.com/ZentWorks/ZentContainer/internal/version"
)

const defaultAgentUpdateImage = "ghcr.io/zentworks/zentcontainer:latest"

func composeRecreateFallbackAllowed(currentImage, targetImage string) bool {
	// Docker Compose records source paths from the Compose client's point of
	// view. If those paths cannot be mounted by the daemon, exact recreation is
	// safe only when the image reference itself stays unchanged.
	return strings.TrimSpace(currentImage) != "" && strings.TrimSpace(currentImage) == strings.TrimSpace(targetImage)
}

type selfMountInfo struct {
	Type        string `json:"Type"`
	Destination string `json:"Destination"`
}

func dataDirHasPersistentBacking(dataDir string, mounts []selfMountInfo) bool {
	dataDir = filepath.Clean(dataDir)
	bestLen := -1
	bestType := ""
	for _, m := range mounts {
		dst := filepath.Clean(strings.TrimSpace(m.Destination))
		if dst == "." || dst == "" {
			continue
		}
		covers := dst == dataDir || (dst != "/" && strings.HasPrefix(dataDir, dst+string(os.PathSeparator))) || dst == "/"
		if !covers || len(dst) <= bestLen {
			continue
		}
		bestLen = len(dst)
		bestType = strings.ToLower(strings.TrimSpace(m.Type))
	}
	return bestLen >= 0 && (bestType == "bind" || bestType == "volume")
}

type agentSelfUpdateRequest struct {
	Image string `json:"image,omitempty"`
}
type agentSelfUpdateResponse struct {
	JobID          string `json:"job_id"`
	Mode           string `json:"mode"`
	Image          string `json:"image"`
	CurrentVersion string `json:"current_version"`
	TargetVersion  string `json:"target_version"`
	Status         string `json:"status"`
}

func (a *App) imageBinaryVersion(ctx context.Context, image string) (string, error) {
	d, err := a.docker()
	if err != nil {
		return "", err
	}
	id, err := d.ContainerCreate(ctx, "", dockerx.CreateContainerRequest{Image: image, Cmd: []string{"version"}, HostConfig: dockerx.HostConfig{NetworkMode: "none", CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges"}}})
	if err != nil {
		return "", err
	}
	defer d.ContainerRemove(context.Background(), id, true)
	if err := d.ContainerAction(ctx, id, "start"); err != nil {
		return "", err
	}
	if err := d.ContainerWait(ctx, id); err != nil {
		return "", err
	}
	out, err := d.ContainerOutput(ctx, id, 20, false)
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(string(out))
	if v == "" {
		return "", errors.New("updated image returned no ZentContainer version")
	}
	if i := strings.LastIndex(v, "\n"); i >= 0 {
		v = strings.TrimSpace(v[i+1:])
	}
	return v, nil
}

func (a *App) composeSelfUpdatePreflight(ctx context.Context, workingDir, service string, files []string) error {
	d, err := a.docker()
	if err != nil {
		return err
	}
	img, err := a.helperImage(ctx)
	if err != nil {
		return err
	}
	args := []string{"helper", "compose-check", service}
	args = append(args, files...)
	id, err := d.ContainerCreate(ctx, "", dockerx.CreateContainerRequest{Image: img, Cmd: args, WorkingDir: "/workspace", HostConfig: dockerx.HostConfig{Binds: []string{workingDir + ":/workspace:ro"}, NetworkMode: "none", CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges"}}})
	if err != nil {
		return err
	}
	defer d.ContainerRemove(context.Background(), id, true)
	if err := d.ContainerAction(ctx, id, "start"); err != nil {
		return err
	}
	if err := d.ContainerWait(ctx, id); err != nil {
		return err
	}
	raw, _ := d.ContainerInspect(ctx, id)
	var st struct {
		State struct {
			ExitCode int `json:"ExitCode"`
		} `json:"State"`
	}
	_ = json.Unmarshal(raw, &st)
	if st.State.ExitCode != 0 {
		out, _ := d.ContainerOutput(ctx, id, 100, false)
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = "Compose source preflight failed"
		}
		return errors.New(msg)
	}
	return nil
}

func (a *App) cleanOldAgentUpdateHelpers(ctx context.Context, d *dockerx.Client) {
	items, err := d.Containers(ctx, true)
	if err != nil {
		return
	}
	for _, c := range items {
		if c.Labels["io.zentcontainer.agent-update"] == "true" && c.State != "running" {
			// Never remove a rollback container from generic cleanup. A failed
			// standalone update may have left it behind as the last recoverable copy.
			// Successful backups are removed only after the replacement Agent has
			// reconnected over mTLS and the helper itself exited successfully.
			_ = d.ContainerRemove(context.Background(), c.ID, true)
		}
	}
}
func (a *App) activeAgentUpdateHelper(ctx context.Context, d *dockerx.Client) bool {
	items, err := d.Containers(ctx, true)
	if err != nil {
		return false
	}
	for _, c := range items {
		if c.Labels["io.zentcontainer.agent-update"] == "true" && c.State == "running" {
			return true
		}
	}
	return false
}

func (a *App) agentSelfUpdate(w http.ResponseWriter, r *http.Request) {
	if a.db.Role() != "agent" {
		errorJSON(w, 404, "not_agent", "This instance is not an Agent")
		return
	}
	var in agentSelfUpdateRequest
	if r.Body != nil {
		if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&in); err != nil && !errors.Is(err, io.EOF) {
			errorJSON(w, 400, "invalid_json", "Invalid update request")
			return
		}
	}
	image := strings.TrimSpace(in.Image)
	if image == "" {
		image = defaultAgentUpdateImage
	}
	d, err := a.docker()
	if err != nil {
		errorJSON(w, 503, "docker_unavailable", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Minute)
	defer cancel()
	a.cleanOldAgentUpdateHelpers(ctx, d)
	if a.activeAgentUpdateHelper(ctx, d) {
		errorJSON(w, 409, "agent_update_running", "An Agent self-update is already running")
		return
	}
	selfID, raw, err := a.selfContainerInspect(ctx, d)
	if err != nil {
		errorJSON(w, 502, "self_inspect_failed", err.Error())
		return
	}
	var ci struct {
		Image  string `json:"Image"`
		Config struct {
			Image  string            `json:"Image"`
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
		Mounts []selfMountInfo `json:"Mounts"`
	}
	if err := json.Unmarshal(raw, &ci); err != nil {
		errorJSON(w, 500, "self_inspect_decode_failed", err.Error())
		return
	}
	dataDir := filepath.Clean(a.cfg.DataDir)
	if !dataDirHasPersistentBacking(dataDir, ci.Mounts) {
		errorJSON(w, http.StatusConflict, "agent_data_not_persistent", "Agent self-update is blocked because the configured data directory is not backed by a bind mount or named volume. Updating would risk losing pairing and certificates.")
		return
	}
	labels := ci.Config.Labels
	project := strings.TrimSpace(labels["com.docker.compose.project"])
	service := strings.TrimSpace(labels["com.docker.compose.service"])
	mode := "standalone"
	workingDir := ""
	files := []string{}
	if project != "" || service != "" {
		if project == "" || service == "" {
			errorJSON(w, 409, "compose_metadata_incomplete", "The Agent has incomplete Docker Compose labels and cannot be updated safely")
			return
		}
		// For the normal self-update case (:latest -> newer :latest digest),
		// exact inspect recreation is safer than re-running Compose because the
		// original Compose client may have supplied shell/UI environment values
		// that cannot be reconstructed here. The image reference remains unchanged,
		// so the Compose source of truth is not modified or contradicted.
		if composeRecreateFallbackAllowed(ci.Config.Image, image) {
			mode = "compose-recreate"
		} else {
			mode = "compose"
			workingDir, files, err = composeConfigPaths(labels)
			if err == nil {
				err = a.composeSelfUpdatePreflight(ctx, workingDir, service, files)
			}
			if err != nil {
				errorJSON(w, 409, "compose_source_unavailable", "Compose source is not reachable from the Docker host and the requested image reference differs from the Compose service. Update the Compose source or use the same image reference.")
				return
			}
		}
	}
	if err := d.ImagePullProgress(ctx, image, a.registryAuthForImage(image), nil); err != nil {
		errorJSON(w, 502, "agent_update_pull_failed", err.Error())
		return
	}
	targetImageID := ""
	if iraw, ierr := d.ImageInspect(ctx, image); ierr == nil {
		var im struct {
			ID string `json:"Id"`
		}
		if json.Unmarshal(iraw, &im) == nil {
			targetImageID = strings.TrimSpace(im.ID)
			if targetImageID != "" && targetImageID == strings.TrimSpace(ci.Image) {
				writeJSON(w, agentSelfUpdateResponse{Mode: mode, Image: image, CurrentVersion: version.Version, TargetVersion: version.Version, Status: "up_to_date"})
				return
			}
		}
	}
	if targetImageID == "" {
		errorJSON(w, 502, "agent_update_image_invalid", "Pulled Agent image has no Docker image ID")
		return
	}
	targetVersion, err := a.imageBinaryVersion(ctx, image)
	if err != nil {
		errorJSON(w, 502, "agent_update_image_invalid", err.Error())
		return
	}
	helperImage, err := a.helperImage(ctx)
	if err != nil {
		errorJSON(w, 500, "helper_image_unavailable", err.Error())
		return
	}
	jobToken, err := randomHex(8)
	if err != nil {
		errorJSON(w, 500, "job_id_failed", err.Error())
		return
	}
	jobName := "zc-agent-update-" + jobToken
	backupName := "zc-agent-selfupdate-backup-" + jobToken
	cmd := []string{"helper", "self-update-standalone", selfID, image, backupName}
	binds := []string{a.cfg.DockerSocket + ":/var/run/docker.sock:rw"}
	if mode == "compose" {
		cmd = []string{"helper", "self-update-compose", project, service, image, ci.Image}
		cmd = append(cmd, files...)
		binds = append(binds, workingDir+":/workspace:rw")
	}
	helperID, err := d.ContainerCreate(ctx, jobName, dockerx.CreateContainerRequest{Image: helperImage, Cmd: cmd, WorkingDir: "/workspace", Labels: map[string]string{"io.zentcontainer.agent-update": "true", "io.zentcontainer.agent-update.mode": mode, "io.zentcontainer.agent-update.target-version": targetVersion, "io.zentcontainer.agent-update.target-image-id": targetImageID, "io.zentcontainer.agent-update.old-container-id": selfID, "io.zentcontainer.agent-update.backup": backupName}, HostConfig: dockerx.HostConfig{Binds: binds, NetworkMode: "none", CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges"}}})
	if err != nil {
		errorJSON(w, 502, "agent_update_helper_create_failed", err.Error())
		return
	}
	if err := d.ContainerAction(ctx, helperID, "start"); err != nil {
		_ = d.ContainerRemove(context.Background(), helperID, true)
		errorJSON(w, 502, "agent_update_helper_start_failed", err.Error())
		return
	}
	a.db.AddAudit("controller", "agent.self_update", selfID, mode+" | "+version.Version+" -> "+targetVersion+" | "+image)
	writeJSONStatus(w, http.StatusAccepted, agentSelfUpdateResponse{JobID: helperID, Mode: mode, Image: image, CurrentVersion: version.Version, TargetVersion: targetVersion, Status: "restarting"})
}

func (a *App) agentSelfUpdateStatus(w http.ResponseWriter, r *http.Request) {
	if a.db.Role() != "agent" {
		errorJSON(w, 404, "not_agent", "This instance is not an Agent")
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("job_id"))
	if id == "" {
		errorJSON(w, 400, "job_id_required", "job_id is required")
		return
	}
	d, err := a.docker()
	if err != nil {
		errorJSON(w, 503, "docker_unavailable", err.Error())
		return
	}
	raw, err := d.ContainerInspect(r.Context(), id)
	if err != nil {
		errorJSON(w, 404, "agent_update_job_not_found", "Agent update job not found")
		return
	}
	var x struct {
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
		State struct {
			Running  bool `json:"Running"`
			ExitCode int  `json:"ExitCode"`
		} `json:"State"`
	}
	if json.Unmarshal(raw, &x) != nil || x.Config.Labels["io.zentcontainer.agent-update"] != "true" {
		errorJSON(w, 404, "agent_update_job_not_found", "Agent update job not found")
		return
	}
	status := "running"
	msg := "Agent update helper is running"
	if x.State.Running {
		targetVersion := strings.TrimSpace(x.Config.Labels["io.zentcontainer.agent-update.target-version"])
		targetImageID := strings.TrimSpace(x.Config.Labels["io.zentcontainer.agent-update.target-image-id"])
		oldContainerID := strings.TrimSpace(x.Config.Labels["io.zentcontainer.agent-update.old-container-id"])
		currentID, currentRaw, selfErr := a.selfContainerInspect(r.Context(), d)
		currentImageID := ""
		if selfErr == nil {
			var self struct {
				Image string `json:"Image"`
			}
			if json.Unmarshal(currentRaw, &self) == nil {
				currentImageID = strings.TrimSpace(self.Image)
			}
		}
		if targetVersion != "" && targetVersion == version.Version && targetImageID != "" && currentImageID == targetImageID && currentID != "" && currentID != oldContainerID {
			// This endpoint is reachable only through the paired mTLS channel. Commit
			// only when the caller reached a *replacement* container running the exact
			// pulled image. Version alone is insufficient because :latest can be
			// rebuilt without changing the semantic version.
			ackCtx, ackCancel := context.WithTimeout(r.Context(), 3*time.Second)
			_, _ = d.ExecRun(ackCtx, id, []string{"sh", "-c", "touch /tmp/zc-agent-update-ack"})
			ackCancel()
			status = "verifying"
			msg = "Controller reconnected over mTLS to the replacement Agent; finalizing update"
		}
	} else {
		// A completed helper is no longer needed once this status request has
		// captured its exit code and output. Remove it on both success and failure
		// so zc-agent-update-* does not linger in Docker/Unraid.
		defer func() { _ = d.ContainerRemove(context.Background(), id, true) }()
		if x.State.ExitCode == 0 {
			status = "done"
			msg = "Agent update helper completed"
			if backup := strings.TrimSpace(x.Config.Labels["io.zentcontainer.agent-update.backup"]); backup != "" {
				_ = d.ContainerRemove(context.Background(), backup, true)
			}
		} else {
			status = "failed"
			out, _ := d.ContainerOutput(r.Context(), id, 100, false)
			msg = strings.TrimSpace(string(out))
			if msg == "" {
				msg = fmt.Sprintf("Agent update helper exited with code %d", x.State.ExitCode)
			}
		}
	}
	writeJSON(w, map[string]any{"job_id": id, "status": status, "message": msg, "mode": x.Config.Labels["io.zentcontainer.agent-update.mode"], "target_version": x.Config.Labels["io.zentcontainer.agent-update.target-version"], "running_version": version.Version})
}

func (a *App) controllerAgentSelfUpdate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ag, ok, err := a.db.AgentByID(id)
	if err != nil || !ok {
		errorJSON(w, 404, "host_not_found", "Agent not found")
		return
	}
	var in agentSelfUpdateRequest
	if r.Body != nil {
		_ = json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&in)
	}
	b, _ := json.Marshal(in)
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Minute)
	defer cancel()
	resp, err := a.agentRequest(ctx, ag, http.MethodPost, "/agent/api/v1/self-update", bytes.NewReader(b))
	if err != nil {
		errorJSON(w, 502, "agent_unreachable", err.Error())
		return
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(data)
		return
	}
	var out agentSelfUpdateResponse
	if json.Unmarshal(data, &out) != nil {
		errorJSON(w, 502, "invalid_agent_response", "Agent returned an invalid update response")
		return
	}
	if out.Status == "up_to_date" || out.JobID == "" {
		_ = a.db.SetAgentVersion(ag.ID, out.CurrentVersion)
		writeRawJSONStatus(w, http.StatusOK, data)
		return
	}
	go a.waitForUpdatedAgent(ag, out.TargetVersion, out.JobID)
	writeRawJSONStatus(w, http.StatusAccepted, data)
}
func (a *App) controllerAgentSelfUpdateStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ag, ok, err := a.db.AgentByID(id)
	if err != nil || !ok {
		errorJSON(w, 404, "host_not_found", "Agent not found")
		return
	}
	job := strings.TrimSpace(r.URL.Query().Get("job_id"))
	if job == "" {
		errorJSON(w, 400, "job_id_required", "job_id is required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	resp, err := a.agentRequest(ctx, ag, http.MethodGet, "/agent/api/v1/self-update-status?job_id="+job, nil)
	if err != nil {
		errorJSON(w, 503, "agent_restarting", err.Error())
		return
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(data)
		return
	}
	var x map[string]any
	if json.Unmarshal(data, &x) == nil {
		if v := strings.TrimSpace(fmt.Sprint(x["running_version"])); v != "" {
			_ = a.db.SetAgentVersion(id, v)
		}
	}
	writeRawJSON(w, data)
}
func (a *App) waitForUpdatedAgent(ag store.Agent, target, jobID string) {
	deadline := time.Now().Add(7 * time.Minute)
	for time.Now().Before(deadline) {
		time.Sleep(3 * time.Second)
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		v, err := a.probeAgent(ctx, ag)
		cancel()
		if err != nil {
			continue
		}
		got := strings.TrimSpace(fmt.Sprint(v["version"]))
		if got != "" {
			_ = a.db.SetAgentVersion(ag.ID, got)
		}
		if strings.TrimSpace(jobID) == "" {
			if target == "" || got == target {
				return
			}
			continue
		}
		// Always inspect the helper after any successful mTLS probe. On the old
		// Agent this reports "running" without acknowledging anything; on the
		// replacement Agent with the target version, the status endpoint writes the
		// commit acknowledgement. If the helper already rolled back, this also lets
		// the Controller observe "failed" instead of waiting until the full deadline.
		statusCtx, statusCancel := context.WithTimeout(context.Background(), 6*time.Second)
		resp, statusErr := a.agentRequest(statusCtx, ag, http.MethodGet, "/agent/api/v1/self-update-status?job_id="+jobID, nil)
		if statusErr == nil && resp != nil {
			data, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				var st struct {
					Status string `json:"status"`
				}
				if json.Unmarshal(data, &st) == nil && (st.Status == "done" || st.Status == "failed") {
					statusCancel()
					return
				}
			}
		}
		statusCancel()
	}
}
