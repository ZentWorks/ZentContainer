package app

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

func (a *App) projectDiagnostics(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	analysis, err := a.projects.Analyze(name)
	if err != nil {
		errorJSON(w, 400, "project_diagnostics_failed", err.Error())
		return
	}
	status, _ := a.projects.Status(name)
	findings := []finding{}
	if analysis.ComposeFile == "" {
		findings = append(findings, finding{Level: "warn", Title: "Keine Compose-Datei gefunden", Detail: "Das Projekt kann Dateien enthalten, lässt sich aber erst mit einer Compose-Datei starten."})
		writeJSON(w, map[string]any{"findings": findings, "analysis": analysis, "status": status})
		return
	}
	if _, err := a.projects.Validate(name); err != nil {
		findings = append(findings, finding{Level: "bad", Title: "Compose-Konfiguration ist nicht gültig", Detail: err.Error(), Hint: "Öffne die markierte Compose-Datei und korrigiere die Konfiguration."})
	} else {
		findings = append(findings, finding{Level: "good", Title: "Compose-Konfiguration gültig", Detail: analysis.ComposeFile + " wurde erfolgreich geprüft."})
	}
	for _, ef := range analysis.EnvAnalysis {
		for _, v := range ef.Missing {
			var def bool
			for _, x := range analysis.Variables {
				if x.Name == v && x.HasDefault {
					def = true
					break
				}
			}
			if !def {
				findings = append(findings, finding{Level: "warn", Title: "Variable fehlt", Detail: v + " ist in " + ef.Path + " nicht gesetzt.", Hint: "Im .env-Assistenten kann sie mit einem Klick ergänzt werden."})
			}
		}
		if len(ef.Duplicates) > 0 {
			findings = append(findings, finding{Level: "warn", Title: "Doppelte Variablen", Detail: strings.Join(ef.Duplicates, ", ") + " kommen mehrfach in " + ef.Path + " vor."})
		}
	}
	for _, p := range analysis.ReferencedMissing {
		findings = append(findings, finding{Level: "bad", Title: "Referenzierte Datei fehlt", Detail: p, Hint: "Datei im Project Workspace anlegen oder den Pfad in Compose korrigieren."})
	}
	if status.State == "partial" {
		findings = append(findings, finding{Level: "warn", Title: "Projekt läuft nur teilweise", Detail: fmt.Sprintf("%d von %d Services laufen.", status.Running, status.Services), Hint: "Projekt-Logs und Container-Diagnose prüfen."})
	} else if status.State == "running" {
		findings = append(findings, finding{Level: "good", Title: "Alle Services laufen", Detail: fmt.Sprintf("%d Services aktiv.", status.Running)})
	}
	writeJSON(w, map[string]any{"findings": findings, "analysis": analysis, "status": status})
}

func (a *App) projectBuild(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Tag        string `json:"tag"`
		Dockerfile string `json:"dockerfile"`
		Context    string `json:"context"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	out, err := a.projects.Build(r.PathValue("name"), in.Tag, in.Dockerfile, in.Context)
	if err != nil {
		errorJSON(w, 400, "build_failed", err.Error())
		return
	}
	a.db.AddAudit(a.currentActor(r), "project.build", r.PathValue("name"), in.Tag)
	writeJSON(w, map[string]any{"ok": true, "output": out, "image": in.Tag})
}

func (a *App) projectArchive(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	dir := filepath.Join(a.projects.Root, name)
	if _, err := os.Stat(dir); err != nil {
		errorJSON(w, 404, "project_not_found", err.Error())
		return
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		rel, _ := filepath.Rel(dir, p)
		if rel == "." {
			return nil
		}
		base := d.Name()
		if rel == ".history" || strings.HasPrefix(rel, ".history"+string(os.PathSeparator)) || strings.HasPrefix(strings.ToLower(base), ".smbdelete") {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		f, e := zw.Create(filepath.ToSlash(rel))
		if e != nil {
			return e
		}
		b, e := os.ReadFile(p)
		if e != nil {
			return e
		}
		_, e = f.Write(b)
		return e
	})
	if err == nil {
		err = zw.Close()
	}
	if err != nil {
		errorJSON(w, 500, "archive_failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", safeName(name)+".zip"))
	w.Write(buf.Bytes())
}

func (a *App) projectImport(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 256<<20)
	if err := r.ParseMultipartForm(16 << 20); err != nil {
		errorJSON(w, 400, "import_failed", err.Error())
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		errorJSON(w, 400, "import_failed", "project name is required")
		return
	}
	if err := a.projects.Create(name); err != nil {
		errorJSON(w, 409, "import_failed", err.Error())
		return
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = a.projects.Delete(name)
		}
	}()
	f, _, err := r.FormFile("file")
	if err != nil {
		errorJSON(w, 400, "import_failed", "archive file is required")
		return
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 256<<20))
	if err != nil {
		errorJSON(w, 400, "import_failed", err.Error())
		return
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		errorJSON(w, 400, "import_failed", err.Error())
		return
	}
	for _, zf := range zr.File {
		rel := filepath.ToSlash(filepath.Clean(filepath.FromSlash(zf.Name)))
		if rel == "." || rel == "" {
			continue
		}
		if filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, "../") || strings.HasPrefix(rel, ".history/") || rel == ".history" {
			errorJSON(w, 400, "import_failed", "unsafe archive path")
			return
		}
		if zf.FileInfo().IsDir() {
			if err := a.projects.Mkdir(name, rel); err != nil {
				errorJSON(w, 400, "import_failed", err.Error())
				return
			}
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			errorJSON(w, 400, "import_failed", err.Error())
			return
		}
		b, err := io.ReadAll(io.LimitReader(rc, 100<<20))
		_ = rc.Close()
		if err != nil {
			errorJSON(w, 400, "import_failed", err.Error())
			return
		}
		if err := a.projects.WriteFile(name, rel, b); err != nil {
			errorJSON(w, 400, "import_failed", err.Error())
			return
		}
	}
	if an, _ := a.projects.Analyze(name); an.ComposeFile != "" {
		_ = a.projects.SetComposeFile(name, an.ComposeFile)
	}
	cleanup = false
	a.db.AddAudit(a.currentActor(r), "project.import", name, "")
	writeJSONStatus(w, 201, map[string]any{"ok": true, "name": name})
}

func yamlQ(s string) string { return strconv.Quote(s) }
func (a *App) containerConvertCompose(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	_ = decodeJSONOptional(r, &in)
	d, err := a.docker()
	if err != nil {
		errorJSON(w, 503, "docker_unavailable", err.Error())
		return
	}
	raw, err := d.ContainerInspect(r.Context(), r.PathValue("id"))
	if err != nil {
		errorJSON(w, 502, "docker_error", err.Error())
		return
	}
	var ci map[string]any
	if json.Unmarshal(raw, &ci) != nil {
		errorJSON(w, 500, "decode_error", "invalid inspect response")
		return
	}
	cfg, _ := ci["Config"].(map[string]any)
	labels, _ := cfg["Labels"].(map[string]any)
	if strings.TrimSpace(asString(labels["com.docker.compose.project"])) != "" {
		errorJSON(w, 409, "already_compose", "Container already belongs to a Compose project")
		return
	}
	containerName := strings.TrimPrefix(asString(ci["Name"]), "/")
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = safeName(containerName)
	}
	if err := a.projects.Create(name); err != nil {
		errorJSON(w, 409, "project_create_failed", err.Error())
		return
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = a.projects.Delete(name)
		}
	}()
	hc, _ := ci["HostConfig"].(map[string]any)
	var b strings.Builder
	b.WriteString("services:\n  app:\n    image: " + yamlQ(asString(cfg["Image"])) + "\n    container_name: " + yamlQ(containerName) + "\n")
	if rp, ok := hc["RestartPolicy"].(map[string]any); ok {
		if x := asString(rp["Name"]); x != "" && x != "no" {
			b.WriteString("    restart: " + yamlQ(x) + "\n")
		}
	}
	if env, ok := cfg["Env"].([]any); ok && len(env) > 0 {
		b.WriteString("    environment:\n")
		for _, e := range env {
			b.WriteString("      - " + yamlQ(fmt.Sprint(e)) + "\n")
		}
	}
	if pb, ok := hc["PortBindings"].(map[string]any); ok && len(pb) > 0 {
		b.WriteString("    ports:\n")
		keys := []string{}
		for k := range pb {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			bs, _ := pb[k].([]any)
			for _, x := range bs {
				m, _ := x.(map[string]any)
				hp := asString(m["HostPort"])
				if hp != "" {
					b.WriteString("      - " + yamlQ(hp+":"+k) + "\n")
				}
			}
		}
	}
	volNames := map[string]bool{}
	if mounts, ok := ci["Mounts"].([]any); ok && len(mounts) > 0 {
		b.WriteString("    volumes:\n")
		for _, x := range mounts {
			m, _ := x.(map[string]any)
			src := asString(m["Source"])
			if asString(m["Type"]) == "volume" {
				src = asString(m["Name"])
				volNames[src] = true
			}
			dst := asString(m["Destination"])
			if src != "" && dst != "" {
				mode := ""
				if rw, ok := m["RW"].(bool); ok && !rw {
					mode = ":ro"
				}
				b.WriteString("      - " + yamlQ(src+":"+dst+mode) + "\n")
			}
		}
	}
	nets := []string{}
	if ns, ok := ci["NetworkSettings"].(map[string]any); ok {
		if mm, ok := ns["Networks"].(map[string]any); ok {
			for n := range mm {
				nets = append(nets, n)
			}
		}
	}
	sort.Strings(nets)
	if len(nets) > 0 {
		b.WriteString("    networks:\n")
		for _, n := range nets {
			b.WriteString("      - " + yamlQ(n) + "\n")
		}
	}
	if len(volNames) > 0 {
		b.WriteString("volumes:\n")
		keys := []string{}
		for v := range volNames {
			keys = append(keys, v)
		}
		sort.Strings(keys)
		for _, v := range keys {
			b.WriteString("  " + yamlQ(v) + ":\n    external: true\n")
		}
	}
	if len(nets) > 0 {
		b.WriteString("networks:\n")
		for _, n := range nets {
			b.WriteString("  " + yamlQ(n) + ":\n    external: true\n")
		}
	}
	if err := a.projects.WriteFile(name, "compose.yaml", []byte(b.String())); err != nil {
		errorJSON(w, 400, "project_create_failed", err.Error())
		return
	}
	_ = a.projects.SetComposeFile(name, "compose.yaml")
	cleanup = false
	a.db.AddAudit(a.currentActor(r), "container.convert-compose", containerName, name)
	writeJSONStatus(w, 201, map[string]any{"ok": true, "project": name, "compose": b.String()})
}

func decodeJSONOptional(r *http.Request, v any) error {
	if r.Body == nil {
		return nil
	}
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	err := dec.Decode(v)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}
