package app

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ZentWorks/ZentContainer/internal/dockerx"
)

type updateJobStep struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
	Percent int    `json:"percent,omitempty"`
}

type updateJob struct {
	ID          string          `json:"id"`
	ContainerID string          `json:"container_id"`
	Container   string          `json:"container,omitempty"`
	Status      string          `json:"status"`
	Percent     int             `json:"percent"`
	Step        string          `json:"step,omitempty"`
	Message     string          `json:"message,omitempty"`
	Error       string          `json:"error,omitempty"`
	Backup      string          `json:"backup,omitempty"`
	NewID       string          `json:"container_new_id,omitempty"`
	StartedAt   time.Time       `json:"started_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
	FinishedAt  *time.Time      `json:"finished_at,omitempty"`
	Steps       []updateJobStep `json:"steps"`
	Pull        []updateJobStep `json:"pull_layers,omitempty"`
	mu          sync.Mutex      `json:"-"`
}

type updateJobView struct {
	ID          string          `json:"id"`
	ContainerID string          `json:"container_id"`
	Container   string          `json:"container,omitempty"`
	Status      string          `json:"status"`
	Percent     int             `json:"percent"`
	Step        string          `json:"step,omitempty"`
	Message     string          `json:"message,omitempty"`
	Error       string          `json:"error,omitempty"`
	Backup      string          `json:"backup,omitempty"`
	NewID       string          `json:"container_new_id,omitempty"`
	StartedAt   time.Time       `json:"started_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
	FinishedAt  *time.Time      `json:"finished_at,omitempty"`
	Steps       []updateJobStep `json:"steps"`
	Pull        []updateJobStep `json:"pull_layers,omitempty"`
}

type updateFailure struct {
	Status  int
	Code    string
	Message string
}

func (e *updateFailure) Error() string { return e.Message }
func updateFail(status int, code, message string) *updateFailure {
	return &updateFailure{Status: status, Code: code, Message: message}
}

type updateResult struct{ ContainerID, Backup string }
type updateProgress func(step, status, message string, percent int, pull *dockerx.ImagePullProgressEvent)

func newUpdateJob(id, containerID string) *updateJob {
	j := &updateJob{ID: id, ContainerID: containerID, Status: "running", StartedAt: time.Now(), UpdatedAt: time.Now()}
	for _, id := range []string{"inspect", "pull", "stop", "network", "recreate", "restore_network", "start", "health", "rollback", "complete"} {
		j.Steps = append(j.Steps, updateJobStep{ID: id, Status: "waiting"})
	}
	return j
}
func (j *updateJob) snapshot() updateJobView {
	j.mu.Lock()
	defer j.mu.Unlock()
	return updateJobView{
		ID: j.ID, ContainerID: j.ContainerID, Container: j.Container, Status: j.Status, Percent: j.Percent, Step: j.Step, Message: j.Message, Error: j.Error, Backup: j.Backup, NewID: j.NewID, StartedAt: j.StartedAt, UpdatedAt: j.UpdatedAt, FinishedAt: j.FinishedAt,
		Steps: append([]updateJobStep(nil), j.Steps...), Pull: append([]updateJobStep(nil), j.Pull...),
	}
}

func (j *updateJob) set(step, status, msg string, pct int, pull *dockerx.ImagePullProgressEvent) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.UpdatedAt = time.Now()
	j.Step = step
	j.Message = msg
	if pct >= 0 && pct > j.Percent {
		j.Percent = pct
	}
	for i := range j.Steps {
		if j.Steps[i].ID == step {
			j.Steps[i].Status = status
			j.Steps[i].Message = msg
			if pct >= 0 {
				j.Steps[i].Percent = pct
			}
			break
		}
	}
	if pull != nil && pull.ID != "" {
		idx := -1
		for i := range j.Pull {
			if j.Pull[i].ID == pull.ID {
				idx = i
				break
			}
		}
		ps := updateJobStep{ID: pull.ID, Status: pull.Status, Message: pull.Progress}
		if pull.ProgressDetail.Total > 0 {
			ps.Percent = int(pull.ProgressDetail.Current * 100 / pull.ProgressDetail.Total)
			if ps.Percent > 100 {
				ps.Percent = 100
			}
		}
		if idx < 0 {
			j.Pull = append(j.Pull, ps)
		} else {
			j.Pull[idx] = ps
		}
	}
}
func (j *updateJob) finish(res updateResult, err error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	now := time.Now()
	j.UpdatedAt = now
	j.FinishedAt = &now
	if err != nil {
		j.Status = "failed"
		j.Error = err.Error()
		for i := range j.Steps {
			if j.Steps[i].ID == j.Step && j.Steps[i].Status == "running" {
				j.Steps[i].Status = "error"
				j.Steps[i].Message = err.Error()
				break
			}
		}
	} else {
		j.Status = "done"
		j.Percent = 100
		j.NewID = res.ContainerID
		j.Backup = res.Backup
		j.Step = "complete"
		j.Message = "Update completed"
	}
}

func (a *App) updateJobStart(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	jobID, err := randomHex(12)
	if err != nil {
		errorJSON(w, 500, "job_id_failed", err.Error())
		return
	}
	j := newUpdateJob(jobID, id)
	a.updateJobsMu.Lock()
	if a.updateJobs == nil {
		a.updateJobs = map[string]*updateJob{}
	}
	for _, existing := range a.updateJobs {
		s := existing.snapshot()
		if s.ContainerID == id && s.Status == "running" {
			a.updateJobsMu.Unlock()
			errorJSON(w, http.StatusConflict, "update_already_running", "An update is already running for this container")
			return
		}
	}
	a.updateJobs[jobID] = j
	a.updateJobsMu.Unlock()
	actor := a.currentActor(r)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		res, err := a.performContainerUpdate(ctx, id, actor, j.set)
		j.finish(res, err)
		a.pruneUpdateJobs()
	}()
	writeJSONStatus(w, http.StatusAccepted, map[string]any{"job_id": jobID, "status": "running"})
}
func (a *App) updateJobStatus(w http.ResponseWriter, r *http.Request) {
	jobID := strings.TrimSpace(r.URL.Query().Get("job_id"))
	a.updateJobsMu.Lock()
	j := a.updateJobs[jobID]
	a.updateJobsMu.Unlock()
	if j == nil || j.ContainerID != r.PathValue("id") {
		errorJSON(w, 404, "update_job_not_found", "Update job not found")
		return
	}
	writeJSON(w, j.snapshot())
}
func (a *App) pruneUpdateJobs() {
	cutoff := time.Now().Add(-2 * time.Hour)
	a.updateJobsMu.Lock()
	defer a.updateJobsMu.Unlock()
	for id, j := range a.updateJobs {
		s := j.snapshot()
		if s.FinishedAt != nil && s.FinishedAt.Before(cutoff) {
			delete(a.updateJobs, id)
		}
	}
}

func (a *App) performContainerUpdate(ctx context.Context, id, actor string, progress updateProgress) (updateResult, error) {
	set := func(step, status, msg string, p int) {
		if progress != nil {
			progress(step, status, msg, p, nil)
		}
	}
	set("inspect", "running", "Inspecting container", 2)
	d, err := a.docker()
	if err != nil {
		return updateResult{}, updateFail(503, "docker_unavailable", err.Error())
	}
	raw, err := d.ContainerInspect(ctx, id)
	if err != nil {
		return updateResult{}, updateFail(502, "docker_error", err.Error())
	}
	var ci map[string]any
	if err := json.Unmarshal(raw, &ci); err != nil {
		return updateResult{}, updateFail(500, "decode_error", err.Error())
	}
	name := strings.TrimPrefix(asString(ci["Name"]), "/")
	configMap, _ := ci["Config"].(map[string]any)
	if progress != nil {
		set("inspect", "done", "Container inspected", 5)
	}
	if labels, ok := configMap["Labels"].(map[string]any); ok {
		ls := map[string]string{}
		for k, v := range labels {
			ls[k] = asString(v)
		}
		if project := strings.TrimSpace(asString(labels["com.docker.compose.project"])); project != "" && !zentContainerStandaloneLabels(ls) {
			return updateResult{}, updateFail(409, "compose_managed", "This container is managed by Compose project "+project+". Update the project instead.")
		}
	}
	hostConfig, _ := ci["HostConfig"].(map[string]any)
	state, _ := ci["State"].(map[string]any)
	running, _ := state["Running"].(bool)
	imageRef := strings.TrimSpace(asString(configMap["Image"]))
	if imageRef == "" {
		return updateResult{}, updateFail(400, "no_image", "Container has no image reference")
	}
	networkSnapshot, err := networkSnapshotFromInspect(raw)
	if err != nil {
		return updateResult{}, updateFail(500, "network_snapshot_failed", err.Error())
	}
	set("pull", "running", "Pulling image", 7)
	layers := map[string][2]int64{}
	err = d.ImagePullProgress(ctx, imageRef, a.registryAuthForImage(imageRef), func(ev dockerx.ImagePullProgressEvent) {
		if ev.ProgressDetail.Total > 0 {
			layers[ev.ID] = [2]int64{ev.ProgressDetail.Current, ev.ProgressDetail.Total}
		}
		var cur, total int64
		for _, x := range layers {
			cur += x[0]
			total += x[1]
		}
		pp := 0
		if total > 0 {
			pp = int(cur * 100 / total)
			if pp > 100 {
				pp = 100
			}
		}
		if progress != nil {
			progress("pull", "running", strings.TrimSpace(ev.Status), 7+pp*28/100, &ev)
		}
	})
	if err != nil {
		return updateResult{}, updateFail(502, "pull_failed", err.Error())
	}
	set("pull", "done", "Image pulled", 35)
	if running {
		set("stop", "running", "Stopping container", 37)
		if err := d.ContainerAction(ctx, id, "stop"); err != nil {
			return updateResult{}, updateFail(502, "stop_failed", err.Error())
		}
		set("stop", "done", "Container stopped", 43)
	} else {
		set("stop", "done", "Container already stopped", 43)
	}
	backup := "zc-backup-" + safeName(name) + "-" + strconv.FormatInt(time.Now().Unix(), 10)
	if err := d.ContainerRename(ctx, id, backup); err != nil {
		if running {
			_ = d.ContainerAction(context.Background(), id, "start")
		}
		return updateResult{}, updateFail(502, "backup_failed", err.Error())
	}
	restoreOld := func() string {
		parts := []string{}
		if err := d.ContainerRename(context.Background(), id, name); err != nil {
			parts = append(parts, "rename: "+err.Error())
		}
		if err := connectMissingNetworkSnapshot(context.Background(), d, id, networkSnapshot); err != nil {
			parts = append(parts, "network restore: "+err.Error())
		}
		if running {
			if err := d.ContainerAction(context.Background(), id, "start"); err != nil {
				parts = append(parts, "start: "+err.Error())
			}
		}
		return strings.Join(parts, "; ")
	}
	set("network", "running", "Releasing previous network identity", 45)
	if err := disconnectNetworkSnapshot(ctx, d, id, networkSnapshot); err != nil {
		set("network", "error", "Could not release the previous network identity: "+err.Error(), -1)
		set("rollback", "running", "Restoring previous container", 54)
		re := restoreOld()
		msg := "Could not release the previous network identity: " + err.Error()
		if re != "" {
			msg += "; restore warning: " + re
			set("rollback", "error", "Previous container restore completed with warnings", 56)
		} else {
			set("rollback", "done", "Previous container restored", 56)
		}
		return updateResult{}, updateFail(502, "network_handoff_failed", msg)
	}
	set("network", "done", "Network identity released", 52)
	labels, _ := configMap["Labels"].(map[string]any)
	if labels == nil {
		labels = map[string]any{}
	}
	labels["io.zentcontainer.managed"] = "true"
	configMap["Labels"] = labels
	body := map[string]any{}
	for k, v := range configMap {
		body[k] = v
	}
	body["HostConfig"] = hostConfig
	if networking := networkingConfigForCreate(networkSnapshot); networking != nil {
		body["NetworkingConfig"] = networking
	}
	for _, att := range networkSnapshot.Attachments {
		if att.Name == networkSnapshot.Primary {
			if mac := strings.TrimSpace(asString(att.Endpoint["MacAddress"])); mac != "" {
				body["MacAddress"] = mac
			}
			break
		}
	}
	set("recreate", "running", "Creating replacement container", 55)
	newID, err := d.ContainerCreateMap(ctx, name, body)
	if err != nil {
		set("recreate", "error", "Replacement container could not be created: "+err.Error(), -1)
		set("rollback", "running", "Restoring previous container", 60)
		re := restoreOld()
		msg := err.Error()
		if re != "" {
			msg += "; previous container restore warning: " + re
			set("rollback", "error", "Previous container restore completed with warnings", 62)
		} else {
			set("rollback", "done", "Previous container restored", 62)
		}
		return updateResult{}, updateFail(502, "recreate_failed", msg)
	}
	set("recreate", "done", "Replacement container created", 68)
	rollbackNew := func(failedStep, code, message string) error {
		set(failedStep, "error", message, -1)
		set("rollback", "running", "Restoring previous container", 90)
		_ = d.ContainerRemove(context.Background(), newID, true)
		re := restoreOld()
		if re != "" {
			message += "; previous container restore warning: " + re
			set("rollback", "error", "Previous container restore completed with warnings", 94)
		} else {
			set("rollback", "done", "Previous container restored", 94)
		}
		return updateFail(502, code, message)
	}
	set("restore_network", "running", "Restoring network identity", 70)
	if err := connectNetworkSnapshot(ctx, d, newID, networkSnapshot, true); err != nil {
		return updateResult{}, rollbackNew("restore_network", "network_restore_failed", "Replacement could not restore all networks: "+err.Error())
	}
	newRaw, err := d.ContainerInspect(ctx, newID)
	if err != nil {
		return updateResult{}, rollbackNew("restore_network", "network_verify_failed", "Replacement could not be inspected after recreate: "+err.Error())
	}
	if err := verifyNetworkSnapshot(newRaw, networkSnapshot); err != nil {
		return updateResult{}, rollbackNew("restore_network", "network_verify_failed", "Replacement network identity verification failed: "+err.Error())
	}
	set("restore_network", "done", "Network identity restored", 80)
	if running {
		set("start", "running", "Starting container", 82)
		if err := d.ContainerAction(ctx, newID, "start"); err != nil {
			return updateResult{}, rollbackNew("start", "start_failed", "New container failed; old container restored: "+err.Error())
		}
		set("start", "done", "Container started", 88)
	} else {
		set("start", "done", "Container remains stopped", 88)
	}
	if running {
		set("health", "running", "Checking container health", 90)
		ht := time.Duration(a.getRuntimeSettings().HealthTimeoutSeconds) * time.Second
		if err := waitContainerHealthy(ctx, d, newID, ht); err != nil {
			return updateResult{}, rollbackNew("health", "healthcheck_failed", "New container failed health verification; previous container restored: "+err.Error())
		}
		set("health", "done", "Health check passed", 98)
	} else {
		set("health", "done", "Health check not required", 98)
	}
	a.db.AddAudit(actor, "container.update", name, "backup="+backup)
	set("complete", "done", "Update completed", 100)
	return updateResult{ContainerID: newID, Backup: backup}, nil
}
