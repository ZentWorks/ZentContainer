package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/ZentWorks/ZentContainer/internal/dockerx"
	"github.com/ZentWorks/ZentContainer/internal/version"
)

const (
	defaultControllerUpdateImage      = "ghcr.io/zentworks/zentcontainer:latest"
	controllerSelfUpdateContinuityKey = "self_update_continuity"
)

type controllerSelfUpdateRequest struct {
	Image string `json:"image,omitempty"`
}

type controllerSelfUpdateResponse struct {
	JobID          string `json:"job_id,omitempty"`
	Mode           string `json:"mode"`
	Image          string `json:"image"`
	CurrentVersion string `json:"current_version"`
	TargetVersion  string `json:"target_version"`
	Status         string `json:"status"`
}

func (a *App) controllerSelfUpdate(w http.ResponseWriter, r *http.Request) {
	if a.db.Role() != "controller" {
		errorJSON(w, 404, "not_controller", "This instance is not a Controller")
		return
	}
	var in controllerSelfUpdateRequest
	if r.Body != nil {
		if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&in); err != nil && !errors.Is(err, io.EOF) {
			errorJSON(w, 400, "invalid_json", "Invalid update request")
			return
		}
	}
	image := strings.TrimSpace(in.Image)
	if image == "" {
		image = defaultControllerUpdateImage
	}
	d, err := a.docker()
	if err != nil {
		errorJSON(w, 503, "docker_unavailable", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Minute)
	defer cancel()
	a.cleanOldControllerUpdateHelpers(ctx, d)
	if a.activeControllerUpdateHelper(ctx, d) {
		errorJSON(w, 409, "controller_update_running", "A ZentContainer self-update is already running")
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
		errorJSON(w, 409, "controller_data_not_persistent", "ZentContainer self-update is blocked because the data directory is not backed by a bind mount or named volume.")
		return
	}

	labels := ci.Config.Labels
	project := strings.TrimSpace(labels["com.docker.compose.project"])
	service := strings.TrimSpace(labels["com.docker.compose.service"])
	mode := "standalone"
	workingDir := ""
	files := []string{}
	if project != "" && service != "" {
		// Same-reference self-updates intentionally preserve the exact running
		// Docker configuration instead of re-evaluating Compose variables in a
		// different client environment. This prevents a valid Compose file from
		// silently resolving ZC_DATA_DIR or other variables to different values.
		if composeRecreateFallbackAllowed(ci.Config.Image, image) {
			mode = "compose-recreate"
		} else {
			wd, fs, sourceErr := composeConfigPaths(labels)
			if sourceErr == nil {
				sourceErr = a.composeSelfUpdatePreflight(ctx, wd, service, fs)
			}
			if sourceErr != nil {
				errorJSON(w, 409, "compose_source_unavailable", "Compose source is not reachable from the Docker host and the requested image reference differs from the Compose service. Update the Compose source or use the same image reference.")
				return
			}
			mode = "compose"
			workingDir = wd
			files = fs
		}
	}
	if err := d.ImagePullProgress(ctx, image, a.registryAuthForImage(image), nil); err != nil {
		errorJSON(w, 502, "controller_update_pull_failed", err.Error())
		return
	}
	targetImageID := ""
	if iraw, e := d.ImageInspect(ctx, image); e == nil {
		var im struct {
			ID string `json:"Id"`
		}
		if json.Unmarshal(iraw, &im) == nil {
			targetImageID = strings.TrimSpace(im.ID)
		}
	}
	if targetImageID == "" {
		errorJSON(w, 502, "controller_update_image_invalid", "Pulled image has no Docker image ID")
		return
	}
	if targetImageID == strings.TrimSpace(ci.Image) {
		writeJSON(w, controllerSelfUpdateResponse{Mode: mode, Image: image, CurrentVersion: version.Version, TargetVersion: version.Version, Status: "up_to_date"})
		return
	}
	targetVersion, err := a.imageBinaryVersion(ctx, image)
	if err != nil {
		errorJSON(w, 502, "controller_update_image_invalid", err.Error())
		return
	}
	helperImage, err := a.helperImage(ctx)
	if err != nil {
		errorJSON(w, 500, "helper_image_unavailable", err.Error())
		return
	}
	tok, err := randomHex(8)
	if err != nil {
		errorJSON(w, 500, "job_id_failed", err.Error())
		return
	}
	jobName := "zc-controller-update-" + tok
	backupName := "zc-controller-selfupdate-backup-" + tok
	// A running HTTP endpoint is not sufficient proof that the replacement loaded
	// this Controller's persistent state: /api/setup also responds on a fresh
	// unconfigured instance. Store a one-time value in the existing SQLite DB and
	// require the replacement to read the same value before the rollback container
	// may be deleted.
	if err := a.db.SetSetting(controllerSelfUpdateContinuityKey, tok); err != nil {
		errorJSON(w, 500, "controller_continuity_prepare_failed", "Could not prepare persistent Controller continuity check: "+err.Error())
		return
	}
	continuityOwned := true
	cleanupContinuity := func() {
		if continuityOwned {
			_ = a.db.DeleteSetting(controllerSelfUpdateContinuityKey)
		}
	}
	cmd := []string{"helper", "self-update-controller-standalone", selfID, image, backupName}
	binds := []string{a.cfg.DockerSocket + ":/var/run/docker.sock:rw"}
	if mode == "compose" {
		cmd = []string{"helper", "self-update-controller-compose", project, service, image, ci.Image}
		cmd = append(cmd, files...)
		binds = append(binds, workingDir+":/workspace:rw")
	}
	helperID, err := d.ContainerCreate(ctx, jobName, dockerx.CreateContainerRequest{Image: helperImage, Cmd: cmd, Env: []string{"ZC_SELFUPDATE_DB_PATH=" + a.cfg.DBPath(), "ZC_SELFUPDATE_CONTINUITY_TOKEN=" + tok}, WorkingDir: "/workspace", Labels: map[string]string{
		"io.zentcontainer.controller-update": "true", "io.zentcontainer.controller-update.mode": mode, "io.zentcontainer.controller-update.target-version": targetVersion, "io.zentcontainer.controller-update.target-image-id": targetImageID, "io.zentcontainer.controller-update.old-container-id": selfID, "io.zentcontainer.controller-update.backup": backupName,
	}, HostConfig: dockerx.HostConfig{Binds: binds, NetworkMode: "none", CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges"}}})
	if err != nil {
		cleanupContinuity()
		errorJSON(w, 502, "controller_update_helper_create_failed", err.Error())
		return
	}
	if err := d.ContainerAction(ctx, helperID, "start"); err != nil {
		_ = d.ContainerRemove(context.Background(), helperID, true)
		cleanupContinuity()
		errorJSON(w, 502, "controller_update_helper_start_failed", err.Error())
		return
	}
	// The detached helper owns the continuity marker from this point onward.
	continuityOwned = false
	a.db.AddAudit(a.currentActor(r), "controller.self_update", selfID, mode+" | "+version.Version+" -> "+targetVersion+" | "+image)
	writeJSONStatus(w, http.StatusAccepted, controllerSelfUpdateResponse{JobID: helperID, Mode: mode, Image: image, CurrentVersion: version.Version, TargetVersion: targetVersion, Status: "restarting"})
}

func (a *App) cleanOldControllerUpdateHelpers(ctx context.Context, d *dockerx.Client) {
	items, e := d.Containers(ctx, true)
	if e != nil {
		return
	}
	for _, c := range items {
		if c.Labels["io.zentcontainer.controller-update"] == "true" && c.State != "running" {
			_ = d.ContainerRemove(context.Background(), c.ID, true)
		}
	}
}
func (a *App) activeControllerUpdateHelper(ctx context.Context, d *dockerx.Client) bool {
	items, e := d.Containers(ctx, true)
	if e != nil {
		return false
	}
	for _, c := range items {
		if c.Labels["io.zentcontainer.controller-update"] == "true" && c.State == "running" {
			return true
		}
	}
	return false
}

func (a *App) controllerSelfUpdateStatus(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.URL.Query().Get("job_id"))
	if id == "" {
		errorJSON(w, 400, "job_id_required", "job_id is required")
		return
	}
	d, e := a.docker()
	if e != nil {
		errorJSON(w, 503, "docker_unavailable", e.Error())
		return
	}
	raw, e := d.ContainerInspect(r.Context(), id)
	if e != nil {
		errorJSON(w, 404, "controller_update_job_not_found", "Update job not found")
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
	if json.Unmarshal(raw, &x) != nil || x.Config.Labels["io.zentcontainer.controller-update"] != "true" {
		errorJSON(w, 404, "controller_update_job_not_found", "Update job not found")
		return
	}
	status := "running"
	msg := "ZentContainer update helper is running"
	if !x.State.Running {
		// The stopped helper has already produced every status/log value needed by
		// this response. Remove it after the response is assembled so Docker UIs
		// do not retain zc-controller-update-* containers after an update.
		defer func() { _ = d.ContainerRemove(context.Background(), id, true) }()
		if x.State.ExitCode == 0 {
			status = "done"
			msg = "ZentContainer update completed"
			if b := strings.TrimSpace(x.Config.Labels["io.zentcontainer.controller-update.backup"]); b != "" {
				_ = d.ContainerRemove(context.Background(), b, true)
			}
		} else {
			status = "failed"
			out, _ := d.ContainerOutput(r.Context(), id, 120, false)
			msg = strings.TrimSpace(string(out))
			if msg == "" {
				msg = fmt.Sprintf("update helper exited with code %d", x.State.ExitCode)
			}
		}
	}
	writeJSON(w, map[string]any{"job_id": id, "status": status, "message": msg, "mode": x.Config.Labels["io.zentcontainer.controller-update.mode"], "target_version": x.Config.Labels["io.zentcontainer.controller-update.target-version"], "running_version": version.Version})
}
