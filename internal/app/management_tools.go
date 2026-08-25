package app

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ZentWorks/ZentContainer/internal/dockerx"
)

type finding struct {
	Level  string `json:"level"`
	Title  string `json:"title"`
	Detail string `json:"detail,omitempty"`
	Hint   string `json:"hint,omitempty"`
}

func (a *App) containerPreflight(w http.ResponseWriter, r *http.Request) {
	var in containerInput
	if !decodeJSON(w, r, &in) {
		return
	}
	if err := normalizeContainerInput(&in); err != nil {
		errorJSON(w, 400, "invalid_container", err.Error())
		return
	}
	if r.URL.Query().Get("ports_only") != "1" {
		if err := a.validateContainerResources(r.Context(), in); err != nil {
			errorJSON(w, 400, "invalid_resources", err.Error())
			return
		}
	}
	conf, err := a.containerPortConflicts(r.Context(), in, r.URL.Query().Get("exclude"))
	if err != nil {
		errorJSON(w, 502, "port_check_failed", err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": len(conf) == 0, "conflicts": conf})
}

func (a *App) existingContainerPortConflicts(ctx context.Context, id string) ([]portConflict, error) {
	d, err := a.docker()
	if err != nil {
		return nil, err
	}
	raw, err := d.ContainerInspect(ctx, id)
	if err != nil {
		return nil, err
	}
	var ci map[string]any
	if err := json.Unmarshal(raw, &ci); err != nil {
		return nil, err
	}
	hc, _ := ci["HostConfig"].(map[string]any)
	in := containerInput{Name: "existing", Image: "existing", Ports: []containerPortInput{}}
	if pb, ok := hc["PortBindings"].(map[string]any); ok {
		for key, rawBinds := range pb {
			parts := strings.SplitN(key, "/", 2)
			containerPort := parts[0]
			proto := "tcp"
			if len(parts) > 1 {
				proto = parts[1]
			}
			binds, _ := rawBinds.([]any)
			for _, rb := range binds {
				b, _ := rb.(map[string]any)
				hp := strings.TrimSpace(asString(b["HostPort"]))
				if hp != "" {
					in.Ports = append(in.Ports, containerPortInput{Host: hp, Container: containerPort, Protocol: proto, HostIP: asString(b["HostIp"])})
				}
			}
		}
	}
	return a.containerPortConflicts(ctx, in, id)
}

func (a *App) containerProcesses(w http.ResponseWriter, r *http.Request) {
	d, err := a.docker()
	if err != nil {
		errorJSON(w, 503, "docker_unavailable", err.Error())
		return
	}
	raw, err := d.ContainerTop(r.Context(), r.PathValue("id"))
	if err != nil {
		errorJSON(w, 502, "processes_failed", err.Error())
		return
	}
	writeRawJSON(w, raw)
}

func cleanContainerPath(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		p = "/"
	}
	p = filepath.ToSlash(filepath.Clean("/" + strings.TrimPrefix(p, "/")))
	if p == "/.." || strings.HasPrefix(p, "/../") {
		return "", errors.New("invalid path")
	}
	return p, nil
}

func (a *App) containerFiles(w http.ResponseWriter, r *http.Request) {
	d, err := a.docker()
	if err != nil {
		errorJSON(w, 503, "docker_unavailable", err.Error())
		return
	}
	p, err := cleanContainerPath(r.URL.Query().Get("path"))
	if err != nil {
		errorJSON(w, 400, "invalid_path", err.Error())
		return
	}
	cmd := `p=` + shellQuote(p) + `; for f in "$p"/* "$p"/.[!.]* "$p"/..?*; do [ -e "$f" ] || continue; if [ -d "$f" ]; then t=d; else t=f; fi; s=$(stat -c %s "$f" 2>/dev/null || echo 0); m=$(stat -c %Y "$f" 2>/dev/null || echo 0); printf '%s\t%s\t%s\t%s\n' "$t" "$s" "$m" "${f##*/}"; done`
	out, err := d.ExecRun(r.Context(), r.PathValue("id"), []string{"sh", "-c", cmd})
	if err != nil {
		errorJSON(w, 502, "file_list_failed", "Dateiliste konnte nicht gelesen werden. Das Image benötigt /bin/sh und stat: "+err.Error())
		return
	}
	items := []map[string]any{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 4)
		if len(parts) != 4 {
			continue
		}
		size, _ := strconv.ParseInt(parts[1], 10, 64)
		mod, _ := strconv.ParseInt(parts[2], 10, 64)
		child := strings.TrimSuffix(p, "/") + "/" + parts[3]
		if p == "/" {
			child = "/" + parts[3]
		}
		items = append(items, map[string]any{"name": parts[3], "path": child, "is_dir": parts[0] == "d", "size": size, "modified": mod})
	}
	sort.Slice(items, func(i, j int) bool {
		di, _ := items[i]["is_dir"].(bool)
		dj, _ := items[j]["is_dir"].(bool)
		if di != dj {
			return di
		}
		return strings.ToLower(fmt.Sprint(items[i]["name"])) < strings.ToLower(fmt.Sprint(items[j]["name"]))
	})
	writeJSON(w, items)
}

func archiveSingleFile(tarData []byte) ([]byte, string, error) {
	tr := tar.NewReader(bytes.NewReader(tarData))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, "", err
		}
		if h.FileInfo().IsDir() {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(tr, 6*1024*1024))
		return b, filepath.Base(h.Name), err
	}
	return nil, "", errors.New("file not found in archive")
}
func (a *App) containerFileGet(w http.ResponseWriter, r *http.Request) {
	d, err := a.docker()
	if err != nil {
		errorJSON(w, 503, "docker_unavailable", err.Error())
		return
	}
	p, err := cleanContainerPath(r.URL.Query().Get("path"))
	if err != nil || p == "/" {
		errorJSON(w, 400, "invalid_path", "file path required")
		return
	}
	tarData, err := d.ContainerArchive(r.Context(), r.PathValue("id"), p)
	if err != nil {
		errorJSON(w, 502, "file_read_failed", err.Error())
		return
	}
	b, name, err := archiveSingleFile(tarData)
	if err != nil {
		errorJSON(w, 400, "file_read_failed", err.Error())
		return
	}
	if bytes.IndexByte(b, 0) >= 0 {
		errorJSON(w, 415, "binary_file", "Binärdateien können hier nicht bearbeitet werden.")
		return
	}
	writeJSON(w, map[string]any{"name": name, "path": p, "content": string(b), "size": len(b)})
}
func (a *App) containerFileDownload(w http.ResponseWriter, r *http.Request) {
	d, err := a.docker()
	if err != nil {
		errorJSON(w, 503, "docker_unavailable", err.Error())
		return
	}
	p, err := cleanContainerPath(r.URL.Query().Get("path"))
	if err != nil || p == "/" {
		errorJSON(w, 400, "invalid_path", "file path required")
		return
	}
	tarData, err := d.ContainerArchive(r.Context(), r.PathValue("id"), p)
	if err != nil {
		errorJSON(w, 502, "file_read_failed", err.Error())
		return
	}
	b, name, err := archiveSingleFile(tarData)
	if err != nil {
		errorJSON(w, 400, "file_read_failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	w.Write(b)
}
func (a *App) containerFilePut(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	p, err := cleanContainerPath(in.Path)
	if err != nil || p == "/" {
		errorJSON(w, 400, "invalid_path", "file path required")
		return
	}
	d, err := a.docker()
	if err != nil {
		errorJSON(w, 503, "docker_unavailable", err.Error())
		return
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	b := []byte(in.Content)
	if err := tw.WriteHeader(&tar.Header{Name: filepath.Base(p), Mode: 0644, Size: int64(len(b)), ModTime: time.Now()}); err != nil {
		errorJSON(w, 500, "file_write_failed", err.Error())
		return
	}
	_, _ = tw.Write(b)
	_ = tw.Close()
	if err := d.ContainerArchivePut(r.Context(), r.PathValue("id"), filepath.Dir(p), buf.Bytes()); err != nil {
		errorJSON(w, 502, "file_write_failed", err.Error())
		return
	}
	a.db.AddAudit(a.currentActor(r), "container.file.write", r.PathValue("id"), p)
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) containerDiagnostics(w http.ResponseWriter, r *http.Request) {
	d, err := a.docker()
	if err != nil {
		errorJSON(w, 503, "docker_unavailable", err.Error())
		return
	}
	id := r.PathValue("id")
	raw, err := d.ContainerInspect(r.Context(), id)
	if err != nil {
		errorJSON(w, 502, "docker_error", err.Error())
		return
	}
	var ci map[string]any
	if json.Unmarshal(raw, &ci) != nil {
		errorJSON(w, 500, "decode_error", "invalid inspect response")
		return
	}
	f := []finding{}
	state, _ := ci["State"].(map[string]any)
	running, _ := state["Running"].(bool)
	status := asString(state["Status"])
	exit := int(asFloat(state["ExitCode"]))
	if running {
		f = append(f, finding{Level: "good", Title: "Container läuft", Detail: "Docker meldet den Zustand " + status + "."})
	} else {
		level := "warn"
		if exit != 0 {
			level = "bad"
		}
		f = append(f, finding{Level: level, Title: "Container läuft nicht", Detail: fmt.Sprintf("Status: %s · Exit-Code: %d", status, exit), Hint: "Öffne Logs oder starte den Container nach Behebung der Ursache."})
	}
	if b, _ := state["OOMKilled"].(bool); b {
		f = append(f, finding{Level: "bad", Title: "Vom Speicherschutz beendet", Detail: "Docker meldet OOMKilled. Der Container hatte wahrscheinlich zu wenig RAM.", Hint: "RAM-Limit erhöhen oder Speicherverbrauch der Anwendung prüfen."})
	}
	if e := strings.TrimSpace(asString(state["Error"])); e != "" {
		f = append(f, finding{Level: "bad", Title: "Docker-Fehler", Detail: e})
	}
	if h, ok := state["Health"].(map[string]any); ok {
		hs := asString(h["Status"])
		level := "good"
		if hs == "unhealthy" {
			level = "bad"
		} else if hs != "healthy" {
			level = "warn"
		}
		f = append(f, finding{Level: level, Title: "Healthcheck: " + hs, Detail: "Der im Container konfigurierte Healthcheck meldet diesen Zustand."})
		if logs, ok := h["Log"].([]any); ok && len(logs) > 0 {
			last, _ := logs[len(logs)-1].(map[string]any)
			if out := strings.TrimSpace(asString(last["Output"])); out != "" && hs != "healthy" {
				f = append(f, finding{Level: "info", Title: "Letzte Healthcheck-Ausgabe", Detail: shortText(out, 600)})
			}
		}
	}
	cfg, _ := ci["Config"].(map[string]any)
	hc, _ := ci["HostConfig"].(map[string]any)
	ports := containerInput{Name: "diag", Image: "x", Ports: []containerPortInput{}}
	if pb, ok := hc["PortBindings"].(map[string]any); ok {
		for key, v := range pb {
			cpProto := strings.SplitN(key, "/", 2)
			cp := cpProto[0]
			proto := "tcp"
			if len(cpProto) > 1 {
				proto = cpProto[1]
			}
			if bs, ok := v.([]any); ok {
				for _, bv := range bs {
					bm, _ := bv.(map[string]any)
					hp := asString(bm["HostPort"])
					if hp != "" {
						ports.Ports = append(ports.Ports, containerPortInput{Host: hp, Container: cp, Protocol: proto})
					}
				}
			}
		}
	}
	if conf, _ := a.containerPortConflicts(r.Context(), ports, id); len(conf) > 0 {
		for _, c := range conf {
			f = append(f, finding{Level: "bad", Title: "Port-Konflikt", Detail: fmt.Sprintf("%s/%s wird auch von %s verwendet.", c.HostPort, c.Protocol, c.Container), Hint: func() string {
				if c.Suggestion != "" {
					return "Freier Vorschlag: " + c.Suggestion
				}
				return "Anderen Host-Port wählen."
			}()})
		}
	}
	if mounts, ok := ci["Mounts"].([]any); ok {
		for _, mv := range mounts {
			m, _ := mv.(map[string]any)
			if asString(m["Type"]) == "volume" {
				if _, err := d.VolumeInspect(r.Context(), asString(m["Name"])); err != nil {
					f = append(f, finding{Level: "bad", Title: "Volume fehlt", Detail: asString(m["Name"])})
				}
			}
		}
	}
	if !running {
		if logs, err := d.ContainerLogs(r.Context(), id, 40); err == nil && strings.TrimSpace(string(logs)) != "" {
			f = append(f, finding{Level: "info", Title: "Letzte Logs", Detail: shortText(strings.TrimSpace(string(logs)), 1400)})
		}
	}
	_ = cfg
	writeJSON(w, map[string]any{"status": status, "running": running, "exit_code": exit, "findings": f})
}
func shortText(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
func asFloat(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int:
		return float64(x)
	case int64:
		return float64(x)
	case json.Number:
		f, _ := x.Float64()
		return f
	}
	return 0
}

func (a *App) hardwareDevices(w http.ResponseWriter, r *http.Request) {
	b, err := a.helperHardware(r.Context())
	if err != nil {
		errorJSON(w, 502, "hardware_failed", err.Error())
		return
	}
	var out []map[string]any
	if json.Unmarshal(b, &out) != nil {
		errorJSON(w, 500, "hardware_failed", "invalid hardware response")
		return
	}
	writeJSON(w, out)
}
func (a *App) helperHardware(ctx context.Context) ([]byte, error) {
	d, err := a.docker()
	if err != nil {
		return nil, err
	}
	img, err := a.helperImage(ctx)
	if err != nil {
		return nil, err
	}
	id, err := d.ContainerCreate(ctx, "", dockerx.CreateContainerRequest{Image: img, Cmd: []string{"helper", "hardware"}, HostConfig: dockerx.HostConfig{Binds: []string{"/dev:/hostdev:ro", "/sys:/hostsys:ro"}, NetworkMode: "none", ReadonlyRootfs: true, CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges"}}})
	if err != nil {
		return nil, err
	}
	defer d.ContainerRemove(context.Background(), id, true)
	if err := d.ContainerAction(ctx, id, "start"); err != nil {
		return nil, err
	}
	if err := d.ContainerWait(ctx, id); err != nil {
		return nil, err
	}
	return d.ContainerOutput(ctx, id, 2000, false)
}

func (a *App) resourceMap(w http.ResponseWriter, r *http.Request) {
	d, err := a.docker()
	if err != nil {
		errorJSON(w, 503, "docker_unavailable", err.Error())
		return
	}
	var info map[string]any
	if raw, e := d.Info(r.Context()); e == nil {
		_ = json.Unmarshal(raw, &info)
	}
	capacity := map[string]any{"logical_cpus": int(asFloat(info["NCPU"])), "memory_bytes": int64(asFloat(info["MemTotal"])), "memory_mb": int64(asFloat(info["MemTotal"])) / 1024 / 1024}
	if r.URL.Query().Get("capacity") == "1" {
		writeJSON(w, capacity)
		return
	}
	cs, err := d.Containers(r.Context(), true)
	if err != nil {
		errorJSON(w, 502, "docker_error", err.Error())
		return
	}
	type row struct {
		Name              string  `json:"name"`
		ID                string  `json:"id"`
		CPUSet            string  `json:"cpu_set"`
		CPUs              float64 `json:"cpus"`
		Memory            int64   `json:"memory"`
		MemoryReservation int64   `json:"memory_reservation"`
		Pids              int64   `json:"pids"`
	}
	out := make([]row, len(cs))
	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	for i, c := range cs {
		wg.Add(1)
		go func(i int, c dockerx.ContainerSummary) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			x := row{Name: strings.TrimPrefix(first(c.Names), "/"), ID: c.ID}
			if raw, e := d.ContainerInspect(r.Context(), c.ID); e == nil {
				var ci map[string]any
				if json.Unmarshal(raw, &ci) == nil {
					hc, _ := ci["HostConfig"].(map[string]any)
					x.CPUSet = asString(hc["CpusetCpus"])
					x.CPUs = asFloat(hc["NanoCpus"]) / 1e9
					x.Memory = int64(asFloat(hc["Memory"]))
					x.MemoryReservation = int64(asFloat(hc["MemoryReservation"]))
					x.Pids = int64(asFloat(hc["PidsLimit"]))
				}
			}
			out[i] = x
		}(i, c)
	}
	wg.Wait()
	capacity["containers"] = out
	writeJSON(w, capacity)
}

func (a *App) imageHistory(w http.ResponseWriter, r *http.Request) {
	d, err := a.docker()
	if err != nil {
		errorJSON(w, 503, "docker_unavailable", err.Error())
		return
	}
	raw, err := d.ImageHistory(r.Context(), r.PathValue("id"))
	if err != nil {
		errorJSON(w, 502, "docker_error", err.Error())
		return
	}
	writeRawJSON(w, raw)
}

func (a *App) storageAnalysis(w http.ResponseWriter, r *http.Request) {
	d, err := a.docker()
	if err != nil {
		errorJSON(w, 503, "docker_unavailable", err.Error())
		return
	}
	raw, err := d.SystemDF(r.Context())
	if err != nil {
		errorJSON(w, 502, "docker_error", err.Error())
		return
	}
	var x map[string]any
	if json.Unmarshal(raw, &x) != nil {
		writeRawJSON(w, raw)
		return
	}
	sum := func(key string, field string) int64 {
		var n int64
		if a, ok := x[key].([]any); ok {
			for _, v := range a {
				m, _ := v.(map[string]any)
				n += int64(asFloat(m[field]))
			}
		}
		return n
	}
	reclaimVolumes := int64(0)
	if vs, ok := x["Volumes"].([]any); ok {
		for _, v := range vs {
			m, _ := v.(map[string]any)
			u, _ := m["UsageData"].(map[string]any)
			if int(asFloat(u["RefCount"])) == 0 {
				reclaimVolumes += int64(asFloat(u["Size"]))
			}
		}
	}
	buildTotal := sum("BuildCache", "Size")
	buildReclaim := int64(0)
	if bs, ok := x["BuildCache"].([]any); ok {
		for _, v := range bs {
			m, _ := v.(map[string]any)
			if inUse, _ := m["InUse"].(bool); !inUse {
				buildReclaim += int64(asFloat(m["Size"]))
			}
		}
	}
	writeJSON(w, map[string]any{"raw": x, "summary": map[string]any{"images": sum("Images", "Size"), "containers": sum("Containers", "SizeRw"), "volumes": sumVolumeUsage(x), "build_cache": buildTotal, "reclaimable_volumes": reclaimVolumes, "reclaimable_build_cache": buildReclaim}})
}
func sumVolumeUsage(x map[string]any) int64 {
	var n int64
	if vs, ok := x["Volumes"].([]any); ok {
		for _, v := range vs {
			m, _ := v.(map[string]any)
			u, _ := m["UsageData"].(map[string]any)
			n += int64(asFloat(u["Size"]))
		}
	}
	return n
}
func (a *App) storageCleanup(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Images     bool `json:"images"`
		Containers bool `json:"containers"`
		BuildCache bool `json:"build_cache"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	d, err := a.docker()
	if err != nil {
		errorJSON(w, 503, "docker_unavailable", err.Error())
		return
	}
	out := map[string]any{}
	if in.Containers {
		v, e := d.Call(r.Context(), http.MethodPost, "/containers/prune", map[string]any{})
		if e != nil {
			errorJSON(w, 502, "cleanup_failed", e.Error())
			return
		}
		out["containers"] = json.RawMessage(v)
	}
	if in.Images {
		filters := url.QueryEscape(`{"dangling":{"false":true}}`)
		v, e := d.Call(r.Context(), http.MethodPost, "/images/prune?filters="+filters, map[string]any{})
		if e != nil {
			errorJSON(w, 502, "cleanup_failed", e.Error())
			return
		}
		out["images"] = json.RawMessage(v)
	}
	if in.BuildCache {
		v, e := d.Call(r.Context(), http.MethodPost, "/build/prune?all=1", map[string]any{})
		if e != nil {
			errorJSON(w, 502, "cleanup_failed", e.Error())
			return
		}
		out["build_cache"] = json.RawMessage(v)
	}
	a.db.AddAudit(a.currentActor(r), "storage.cleanup", "docker", fmt.Sprintf("images=%v containers=%v build_cache=%v", in.Images, in.Containers, in.BuildCache))
	writeJSON(w, out)
}

func (a *App) dockerEvents(w http.ResponseWriter, r *http.Request) {
	d, err := a.docker()
	if err != nil {
		errorJSON(w, 503, "docker_unavailable", err.Error())
		return
	}
	hours, _ := strconv.Atoi(r.URL.Query().Get("hours"))
	if hours <= 0 || hours > 168 {
		hours = 24
	}
	until := time.Now().Unix()
	ev, err := d.RecentEvents(r.Context(), until-int64(hours*3600), until)
	if err != nil {
		errorJSON(w, 502, "events_failed", err.Error())
		return
	}
	if len(ev) > 250 {
		ev = ev[len(ev)-250:]
	}
	out := make([]map[string]any, 0, len(ev))
	for i := len(ev) - 1; i >= 0; i-- {
		var m map[string]any
		if json.Unmarshal(ev[i], &m) == nil {
			out = append(out, m)
		}
	}
	writeJSON(w, out)
}
