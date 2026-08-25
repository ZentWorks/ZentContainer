package app

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ZentWorks/ZentContainer/internal/store"
)

type runtimeSettings struct {
	UpdateIntervalHours    int `json:"update_interval_hours"`
	RollbackRetentionHours int `json:"rollback_retention_hours"`
	HealthTimeoutSeconds   int `json:"health_timeout_seconds"`
}

func (a *App) getRuntimeSettings() runtimeSettings {
	s := runtimeSettings{UpdateIntervalHours: 6, RollbackRetentionHours: 24, HealthTimeoutSeconds: 60}
	if v, ok, _ := a.db.GetSetting("update_interval_hours"); ok {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 168 {
			s.UpdateIntervalHours = n
		}
	}
	if v, ok, _ := a.db.GetSetting("rollback_retention_hours"); ok {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 720 {
			s.RollbackRetentionHours = n
		}
	}
	if v, ok, _ := a.db.GetSetting("health_timeout_seconds"); ok {
		if n, err := strconv.Atoi(v); err == nil && n >= 10 && n <= 600 {
			s.HealthTimeoutSeconds = n
		}
	}
	return s
}

func (a *App) settingsGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, a.getRuntimeSettings())
}

func (a *App) settingsPut(w http.ResponseWriter, r *http.Request) {
	var in runtimeSettings
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.UpdateIntervalHours < 1 || in.UpdateIntervalHours > 168 {
		errorJSON(w, 400, "invalid_interval", "Update interval must be between 1 and 168 hours")
		return
	}
	if in.RollbackRetentionHours < 1 || in.RollbackRetentionHours > 720 {
		errorJSON(w, 400, "invalid_retention", "Rollback retention must be between 1 and 720 hours")
		return
	}
	if in.HealthTimeoutSeconds < 10 || in.HealthTimeoutSeconds > 600 {
		errorJSON(w, 400, "invalid_health_timeout", "Health timeout must be between 10 and 600 seconds")
		return
	}
	_ = a.db.SetSetting("update_interval_hours", strconv.Itoa(in.UpdateIntervalHours))
	_ = a.db.SetSetting("rollback_retention_hours", strconv.Itoa(in.RollbackRetentionHours))
	_ = a.db.SetSetting("health_timeout_seconds", strconv.Itoa(in.HealthTimeoutSeconds))
	a.db.AddAudit(a.currentActor(r), "settings.update", "system", "")
	writeJSON(w, a.getRuntimeSettings())
}

func (a *App) startScheduler() {
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			a.schedulerTick()
			<-t.C
		}
	}()
}

func (a *App) schedulerTick() {
	if !a.db.IsSetup() {
		return
	}
	s := a.getRuntimeSettings()
	now := time.Now()
	last := int64(0)
	if v, ok, _ := a.db.GetSetting("last_update_scan"); ok {
		last, _ = strconv.ParseInt(v, 10, 64)
	}
	if last == 0 || now.Sub(time.Unix(last, 0)) >= time.Duration(s.UpdateIntervalHours)*time.Hour {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		_ = a.performUpdateScan(ctx)
		cancel()
		_ = a.db.SetSetting("last_update_scan", strconv.FormatInt(now.Unix(), 10))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	a.cleanupRollbackBackups(ctx, s.RollbackRetentionHours)
	cancel()
}

func (a *App) checkContainerUpdate(ctx context.Context, id string) (store.UpdateCheck, error) {
	d, err := a.docker()
	if err != nil {
		return store.UpdateCheck{}, err
	}
	raw, err := d.ContainerInspect(ctx, id)
	if err != nil {
		return store.UpdateCheck{}, err
	}
	var ci struct {
		Config struct {
			Image string `json:"Image"`
		} `json:"Config"`
		Image string `json:"Image"`
	}
	if err := json.Unmarshal(raw, &ci); err != nil {
		return store.UpdateCheck{}, err
	}
	v := store.UpdateCheck{ResourceID: id, ImageRef: ci.Config.Image, Status: "unknown", CheckedAt: time.Now().Unix()}
	if strings.Contains(ci.Config.Image, "@sha256:") {
		v.Status = "pinned"
		_ = a.db.UpsertUpdateCheck(v)
		return v, nil
	}
	localRaw, err := d.ImageInspect(ctx, ci.Image)
	if err != nil {
		return v, err
	}
	var im struct {
		RepoDigests []string `json:"RepoDigests"`
	}
	_ = json.Unmarshal(localRaw, &im)
	dist, err := d.DistributionInspectAuth(ctx, ci.Config.Image, a.registryAuthForImage(ci.Config.Image))
	if err != nil {
		v.Status = "unknown"
		_ = a.db.UpsertUpdateCheck(v)
		return v, err
	}
	var di struct {
		Descriptor struct {
			Digest string `json:"digest"`
		} `json:"Descriptor"`
	}
	_ = json.Unmarshal(dist, &di)
	for _, rd := range im.RepoDigests {
		if i := strings.LastIndex(rd, "@"); i >= 0 {
			v.CurrentDigest = rd[i+1:]
			if v.CurrentDigest == di.Descriptor.Digest {
				break
			}
		}
	}
	v.RemoteDigest = di.Descriptor.Digest
	v.Status = "current"
	if v.RemoteDigest != "" && v.CurrentDigest != v.RemoteDigest {
		v.Status = "update_available"
	}
	_ = a.db.UpsertUpdateCheck(v)
	return v, nil
}

func (a *App) performUpdateScan(ctx context.Context) error {
	d, err := a.docker()
	if err != nil {
		return err
	}
	containers, err := d.Containers(ctx, true)
	if err != nil {
		return err
	}
	for _, c := range containers {
		if isBackup(c) {
			continue
		}
		_, _ = a.checkContainerUpdate(ctx, c.ID)
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
	return nil
}

func (a *App) cleanupRollbackBackups(ctx context.Context, retentionHours int) {
	d, err := a.docker()
	if err != nil {
		return
	}
	containers, err := d.Containers(ctx, true)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-time.Duration(retentionHours) * time.Hour).Unix()
	for _, c := range containers {
		if !isBackup(c) || c.Created >= cutoff {
			continue
		}
		imageID := c.ImageID
		if err := d.ContainerRemove(ctx, c.ID, true); err != nil {
			continue
		}
		a.db.AddAudit("system", "rollback.cleanup", c.ID, "")
		remaining, _ := d.Containers(ctx, true)
		used := false
		for _, rc := range remaining {
			if rc.ImageID == imageID {
				used = true
				break
			}
		}
		if !used && imageID != "" {
			_ = d.ImageRemove(ctx, imageID, false)
		}
	}
}
