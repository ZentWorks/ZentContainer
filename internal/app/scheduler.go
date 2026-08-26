package app

import (
	"context"
	"encoding/json"
	"hash/fnv"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	_ "time/tzdata"

	"github.com/ZentWorks/ZentContainer/internal/store"
)

type runtimeSettings struct {
	UpdateScanEnabled       bool   `json:"update_scan_enabled"`
	UpdateScanWeekday       int    `json:"update_scan_weekday"`
	UpdateScanHour          int    `json:"update_scan_hour"`
	UpdateScanMinute        int    `json:"update_scan_minute"`
	UpdateScanTimezone      string `json:"update_scan_timezone"`
	UpdateScanJitterMinutes int    `json:"update_scan_jitter_minutes"`
	LastUpdateScan          int64  `json:"last_update_scan"`
	HealthTimeoutSeconds    int    `json:"health_timeout_seconds"`
}

type runtimeSettingsInput struct {
	UpdateScanEnabled    *bool   `json:"update_scan_enabled"`
	UpdateScanWeekday    *int    `json:"update_scan_weekday"`
	UpdateScanHour       *int    `json:"update_scan_hour"`
	UpdateScanMinute     *int    `json:"update_scan_minute"`
	UpdateScanTimezone   *string `json:"update_scan_timezone"`
	HealthTimeoutSeconds *int    `json:"health_timeout_seconds"`
	// Accepted for one release cycle so a stale pre-v0.6.38 WebUI cannot
	// accidentally reset the new weekly schedule. It is intentionally ignored.
	UpdateIntervalHours *int `json:"update_interval_hours"`
}

type updateScanResult struct {
	Checked   int   `json:"checked"`
	Updates   int   `json:"updates"`
	Current   int   `json:"current"`
	Pinned    int   `json:"pinned"`
	Unknown   int   `json:"unknown"`
	Errors    int   `json:"errors"`
	CheckedAt int64 `json:"checked_at"`
}

func boolSetting(v string, fallback bool) bool {
	if b, err := strconv.ParseBool(strings.TrimSpace(v)); err == nil {
		return b
	}
	return fallback
}

func stableUpdateJitter(name string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(strings.TrimSpace(name)))
	return int(h.Sum32() % 15) // 0..14 minutes, stable per host.
}

func (a *App) getRuntimeSettings() runtimeSettings {
	name, _, _ := a.db.GetSetting("instance_name")
	s := runtimeSettings{
		UpdateScanEnabled: true, UpdateScanWeekday: 0, UpdateScanHour: 3, UpdateScanMinute: 0,
		UpdateScanTimezone: "Local", UpdateScanJitterMinutes: stableUpdateJitter(name),
		HealthTimeoutSeconds: 60,
	}
	if v, ok, _ := a.db.GetSetting("update_scan_enabled"); ok {
		s.UpdateScanEnabled = boolSetting(v, true)
	}
	if v, ok, _ := a.db.GetSetting("update_scan_weekday"); ok {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 6 {
			s.UpdateScanWeekday = n
		}
	}
	if v, ok, _ := a.db.GetSetting("update_scan_hour"); ok {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 23 {
			s.UpdateScanHour = n
		}
	}
	if v, ok, _ := a.db.GetSetting("update_scan_minute"); ok {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 59 {
			s.UpdateScanMinute = n
		}
	}
	if v, ok, _ := a.db.GetSetting("update_scan_timezone"); ok && strings.TrimSpace(v) != "" {
		s.UpdateScanTimezone = strings.TrimSpace(v)
	}
	if v, ok, _ := a.db.GetSetting("last_update_scan"); ok {
		s.LastUpdateScan, _ = strconv.ParseInt(v, 10, 64)
	}
	if v, ok, _ := a.db.GetSetting("health_timeout_seconds"); ok {
		if n, err := strconv.Atoi(v); err == nil && n >= 10 && n <= 600 {
			s.HealthTimeoutSeconds = n
		}
	}
	return s
}

func scheduleLocation(name string) (*time.Location, error) {
	name = strings.TrimSpace(name)
	if name == "" || strings.EqualFold(name, "local") {
		return time.Local, nil
	}
	return time.LoadLocation(name)
}

func scheduledWeeklyOccurrence(now time.Time, s runtimeSettings) (time.Time, error) {
	loc, err := scheduleLocation(s.UpdateScanTimezone)
	if err != nil {
		return time.Time{}, err
	}
	n := now.In(loc)
	dayStart := time.Date(n.Year(), n.Month(), n.Day(), 0, 0, 0, 0, loc)
	delta := (int(n.Weekday()) - s.UpdateScanWeekday + 7) % 7
	candidate := dayStart.AddDate(0, 0, -delta).Add(time.Duration(s.UpdateScanHour)*time.Hour + time.Duration(s.UpdateScanMinute+s.UpdateScanJitterMinutes)*time.Minute)
	if candidate.After(n) {
		candidate = candidate.AddDate(0, 0, -7)
	}
	return candidate, nil
}

func (a *App) settingsGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, a.getRuntimeSettings())
}

func (a *App) settingsPut(w http.ResponseWriter, r *http.Request) {
	current := a.getRuntimeSettings()
	original := current
	var in runtimeSettingsInput
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.UpdateScanEnabled != nil {
		current.UpdateScanEnabled = *in.UpdateScanEnabled
	}
	if in.UpdateScanWeekday != nil {
		current.UpdateScanWeekday = *in.UpdateScanWeekday
	}
	if in.UpdateScanHour != nil {
		current.UpdateScanHour = *in.UpdateScanHour
	}
	if in.UpdateScanMinute != nil {
		current.UpdateScanMinute = *in.UpdateScanMinute
	}
	if in.UpdateScanTimezone != nil {
		current.UpdateScanTimezone = strings.TrimSpace(*in.UpdateScanTimezone)
	}
	if in.HealthTimeoutSeconds != nil {
		current.HealthTimeoutSeconds = *in.HealthTimeoutSeconds
	}
	if current.UpdateScanWeekday < 0 || current.UpdateScanWeekday > 6 {
		errorJSON(w, 400, "invalid_update_weekday", "Update weekday must be between 0 and 6")
		return
	}
	if current.UpdateScanHour < 0 || current.UpdateScanHour > 23 || current.UpdateScanMinute < 0 || current.UpdateScanMinute > 59 {
		errorJSON(w, 400, "invalid_update_time", "Update scan time is invalid")
		return
	}
	if current.UpdateScanTimezone == "" {
		current.UpdateScanTimezone = "Local"
	}
	if _, err := scheduleLocation(current.UpdateScanTimezone); err != nil {
		errorJSON(w, 400, "invalid_timezone", "Update scan timezone is invalid")
		return
	}
	if current.HealthTimeoutSeconds < 10 || current.HealthTimeoutSeconds > 600 {
		errorJSON(w, 400, "invalid_health_timeout", "Health timeout must be between 10 and 600 seconds")
		return
	}
	_ = a.db.SetSetting("update_scan_enabled", strconv.FormatBool(current.UpdateScanEnabled))
	_ = a.db.SetSetting("update_scan_weekday", strconv.Itoa(current.UpdateScanWeekday))
	_ = a.db.SetSetting("update_scan_hour", strconv.Itoa(current.UpdateScanHour))
	_ = a.db.SetSetting("update_scan_minute", strconv.Itoa(current.UpdateScanMinute))
	_ = a.db.SetSetting("update_scan_timezone", current.UpdateScanTimezone)
	_ = a.db.SetSetting("health_timeout_seconds", strconv.Itoa(current.HealthTimeoutSeconds))
	if original.UpdateScanEnabled != current.UpdateScanEnabled || original.UpdateScanWeekday != current.UpdateScanWeekday || original.UpdateScanHour != current.UpdateScanHour || original.UpdateScanMinute != current.UpdateScanMinute || original.UpdateScanTimezone != current.UpdateScanTimezone {
		_ = a.db.SetSetting("update_scan_schedule_anchor", strconv.FormatInt(time.Now().Unix(), 10))
	}
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
	if s.UpdateScanEnabled {
		anchor := int64(0)
		if v, ok, _ := a.db.GetSetting("update_scan_schedule_anchor"); ok {
			anchor, _ = strconv.ParseInt(v, 10, 64)
		}
		if s.LastUpdateScan == 0 && anchor == 0 {
			// Fresh installations wait for their first configured weekly window instead
			// of creating an unexpected registry burst immediately after setup.
			anchor = now.Unix()
			_ = a.db.SetSetting("update_scan_schedule_anchor", strconv.FormatInt(anchor, 10))
		}
		effectiveLast := s.LastUpdateScan
		if anchor > effectiveLast {
			effectiveLast = anchor
		}
		if occurrence, err := scheduledWeeklyOccurrence(now, s); err == nil && effectiveLast > 0 && time.Unix(effectiveLast, 0).Before(occurrence) {
			lastAttempt := int64(0)
			if v, ok, _ := a.db.GetSetting("last_update_scan_attempt"); ok {
				lastAttempt, _ = strconv.ParseInt(v, 10, 64)
			}
			if lastAttempt == 0 || now.Sub(time.Unix(lastAttempt, 0)) >= time.Hour {
				_ = a.db.SetSetting("last_update_scan_attempt", strconv.FormatInt(now.Unix(), 10))
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
				res, err := a.performUpdateScan(ctx)
				cancel()
				if err == nil {
					_ = a.db.SetSetting("last_update_scan", strconv.FormatInt(res.CheckedAt, 10))
					a.db.AddAudit("system", "updates.scan", "containers", "checked="+strconv.Itoa(res.Checked)+" updates="+strconv.Itoa(res.Updates)+" errors="+strconv.Itoa(res.Errors))
				}
			}
		}
	}
}

func (a *App) preserveKnownUpdateOnCheckError(v store.UpdateCheck) {
	if prev, ok, _ := a.db.UpdateCheckByResourceID(v.ResourceID); ok && prev.Status == "update_available" {
		return
	}
	_ = a.db.UpsertUpdateCheck(v)
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
		a.preserveKnownUpdateOnCheckError(v)
		return v, err
	}
	var im struct {
		RepoDigests []string `json:"RepoDigests"`
	}
	_ = json.Unmarshal(localRaw, &im)
	dist, err := d.DistributionInspectAuth(ctx, ci.Config.Image, a.registryAuthForImage(ci.Config.Image))
	if err != nil {
		a.preserveKnownUpdateOnCheckError(v)
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

func (a *App) beginUpdateScan() bool {
	a.updateScanMu.Lock()
	defer a.updateScanMu.Unlock()
	if a.updateScanRunning {
		return false
	}
	a.updateScanRunning = true
	return true
}
func (a *App) endUpdateScan() {
	a.updateScanMu.Lock()
	a.updateScanRunning = false
	a.updateScanMu.Unlock()
}

func (a *App) performUpdateScan(ctx context.Context) (updateScanResult, error) {
	res := updateScanResult{CheckedAt: time.Now().Unix()}
	if !a.beginUpdateScan() {
		return res, &updateFailure{Status: http.StatusConflict, Code: "update_scan_running", Message: "An update scan is already running"}
	}
	defer a.endUpdateScan()
	d, err := a.docker()
	if err != nil {
		return res, err
	}
	containers, err := d.Containers(ctx, true)
	if err != nil {
		return res, err
	}
	active := map[string]bool{}
	ids := make([]string, 0, len(containers))
	for _, c := range containers {
		if !isBackup(c) {
			active[c.ID] = true
			ids = append(ids, c.ID)
		}
	}
	if checks, _ := a.db.ListUpdateChecks(); len(checks) > 0 {
		for _, c := range checks {
			if !active[c.ResourceID] {
				_ = a.db.DeleteUpdateCheck(c.ResourceID)
			}
		}
	}
	jobs := make(chan string)
	var wg sync.WaitGroup
	var mu sync.Mutex
	workers := 4
	if len(ids) < workers {
		workers = len(ids)
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range jobs {
				v, e := a.checkContainerUpdate(ctx, id)
				mu.Lock()
				res.Checked++
				switch v.Status {
				case "update_available":
					res.Updates++
				case "current":
					res.Current++
				case "pinned":
					res.Pinned++
				default:
					res.Unknown++
				}
				if e != nil {
					res.Errors++
				}
				mu.Unlock()
			}
		}()
	}
	for _, id := range ids {
		select {
		case jobs <- id:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return res, ctx.Err()
		}
	}
	close(jobs)
	wg.Wait()
	res.CheckedAt = time.Now().Unix()
	return res, nil
}

func (a *App) updateScan(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	res, err := a.performUpdateScan(ctx)
	if err != nil {
		if e, ok := err.(*updateFailure); ok {
			errorJSON(w, e.Status, e.Code, e.Message)
			return
		}
		errorJSON(w, 502, "update_scan_failed", err.Error())
		return
	}
	_ = a.db.SetSetting("last_update_scan", strconv.FormatInt(res.CheckedAt, 10))
	a.db.AddAudit(a.currentActor(r), "updates.scan", "containers", "checked="+strconv.Itoa(res.Checked)+" updates="+strconv.Itoa(res.Updates)+" errors="+strconv.Itoa(res.Errors))
	writeJSON(w, res)
}
