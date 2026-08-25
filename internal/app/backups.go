package app

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ZentWorks/ZentContainer/internal/dockerx"
)

type backupManifest struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Kind      string   `json:"kind"`
	Project   string   `json:"project,omitempty"`
	Volumes   []string `json:"volumes"`
	CreatedAt int64    `json:"created_at"`
	Size      int64    `json:"size"`
	Version   string   `json:"version"`
}

type backupCreateInput struct {
	Kind    string `json:"kind"`
	Project string `json:"project"`
	Volume  string `json:"volume"`
	Stop    bool   `json:"stop"`
}

func (a *App) backupsDir() string { return a.cfg.BackupsDir() }

func (a *App) backupList(w http.ResponseWriter, r *http.Request) {
	_ = os.MkdirAll(a.backupsDir(), 0700)
	ents, err := os.ReadDir(a.backupsDir())
	if err != nil {
		errorJSON(w, 500, "backup_error", err.Error())
		return
	}
	out := []backupManifest{}
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(a.backupsDir(), e.Name(), "manifest.json"))
		if err != nil {
			continue
		}
		var m backupManifest
		if json.Unmarshal(b, &m) == nil {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	writeJSON(w, out)
}

func (a *App) backupCreate(w http.ResponseWriter, r *http.Request) {
	var in backupCreateInput
	if !decodeJSON(w, r, &in) {
		return
	}
	in.Kind = strings.ToLower(strings.TrimSpace(in.Kind))
	in.Project = strings.TrimSpace(in.Project)
	in.Volume = strings.TrimSpace(in.Volume)
	if in.Kind == "" {
		if in.Project != "" {
			in.Kind = "project"
		} else {
			in.Kind = "volume"
		}
	}
	id := time.Now().UTC().Format("20060102T150405.000000000Z") + "-" + mustRandomHex(3)
	dir := filepath.Join(a.backupsDir(), id)
	if err := os.MkdirAll(dir, 0700); err != nil {
		errorJSON(w, 500, "backup_error", err.Error())
		return
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(dir)
		}
	}()
	m := backupManifest{ID: id, Kind: in.Kind, CreatedAt: time.Now().Unix(), Version: "1", Volumes: []string{}}
	switch in.Kind {
	case "project":
		if in.Project == "" {
			errorJSON(w, 400, "invalid_backup", "project is required")
			return
		}
		m.Project = in.Project
		m.Name = in.Project
		if _, err := a.projects.Get(in.Project); err != nil {
			errorJSON(w, 404, "project_not_found", err.Error())
			return
		}
		status, _ := a.projects.Status(in.Project)
		wasRunning := status.Running > 0
		if in.Stop && wasRunning {
			if _, err := a.projects.Stop(in.Project); err != nil {
				errorJSON(w, 502, "project_stop_failed", err.Error())
				return
			}
			defer func() { _, _ = a.projects.Start(in.Project) }()
		}
		if err := archiveProjectDir(a.projects.Root, in.Project, filepath.Join(dir, "project.tar.gz")); err != nil {
			errorJSON(w, 500, "backup_error", err.Error())
			return
		}
		vols, err := a.projectVolumes(r.Context(), in.Project)
		if err != nil {
			errorJSON(w, 502, "backup_error", err.Error())
			return
		}
		m.Volumes = vols
		for _, v := range vols {
			data, _, err := a.helperArchiveDownload(r.Context(), v, "/")
			if err != nil {
				errorJSON(w, 502, "backup_volume_failed", v+": "+err.Error())
				return
			}
			if err := os.WriteFile(filepath.Join(dir, "volume-"+safeName(v)+".tar.gz"), data, 0600); err != nil {
				errorJSON(w, 500, "backup_error", err.Error())
				return
			}
		}
	case "volume":
		if in.Volume == "" {
			errorJSON(w, 400, "invalid_backup", "volume is required")
			return
		}
		m.Name = in.Volume
		m.Volumes = []string{in.Volume}
		data, _, err := a.helperArchiveDownload(r.Context(), in.Volume, "/")
		if err != nil {
			errorJSON(w, 502, "backup_volume_failed", err.Error())
			return
		}
		if err := os.WriteFile(filepath.Join(dir, "volume-"+safeName(in.Volume)+".tar.gz"), data, 0600); err != nil {
			errorJSON(w, 500, "backup_error", err.Error())
			return
		}
	default:
		errorJSON(w, 400, "invalid_backup", "kind must be project or volume")
		return
	}
	m.Size = dirSize(dir)
	raw, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0600); err != nil {
		errorJSON(w, 500, "backup_error", err.Error())
		return
	}
	m.Size = dirSize(dir)
	raw, _ = json.MarshalIndent(m, "", "  ")
	_ = os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0600)
	cleanup = false
	a.db.AddAudit(a.currentActor(r), "backup.create", m.Name, id)
	writeJSONStatus(w, 201, m)
}

func (a *App) backupDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	dir, err := a.safeBackupDir(id)
	if err != nil {
		errorJSON(w, 400, "invalid_backup", err.Error())
		return
	}
	if err := os.RemoveAll(dir); err != nil {
		errorJSON(w, 500, "backup_error", err.Error())
		return
	}
	a.db.AddAudit(a.currentActor(r), "backup.delete", id, "")
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) backupRestore(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	dir, err := a.safeBackupDir(id)
	if err != nil {
		errorJSON(w, 400, "invalid_backup", err.Error())
		return
	}
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		errorJSON(w, 404, "backup_not_found", err.Error())
		return
	}
	var m backupManifest
	if json.Unmarshal(raw, &m) != nil {
		errorJSON(w, 500, "backup_error", "invalid manifest")
		return
	}
	if m.Project != "" {
		oldDir := filepath.Join(a.projects.Root, m.Project)
		rollback := oldDir + ".zc-restore-" + mustRandomHex(3)
		hadOld := false
		if _, err := os.Stat(oldDir); err == nil {
			hadOld = true
			st, _ := a.projects.Status(m.Project)
			if st.Running > 0 {
				_, _ = a.projects.Stop(m.Project)
			}
			if err := os.Rename(oldDir, rollback); err != nil {
				errorJSON(w, 500, "restore_failed", err.Error())
				return
			}
		}
		if err := extractProjectArchive(filepath.Join(dir, "project.tar.gz"), a.projects.Root, m.Project); err != nil {
			if hadOld {
				_ = os.RemoveAll(oldDir)
				_ = os.Rename(rollback, oldDir)
			}
			errorJSON(w, 500, "restore_failed", err.Error())
			return
		}
		if hadOld {
			_ = os.RemoveAll(rollback)
		}
	}
	d, err := a.docker()
	if err != nil {
		errorJSON(w, 503, "docker_unavailable", err.Error())
		return
	}
	existing, _ := d.Volumes(r.Context())
	has := map[string]bool{}
	for _, v := range existing {
		has[v.Name] = true
	}
	for _, v := range m.Volumes {
		if !has[v] {
			if _, err := d.VolumeCreate(r.Context(), v, "local"); err != nil {
				errorJSON(w, 502, "restore_failed", err.Error())
				return
			}
		}
		file := filepath.Join(dir, "volume-"+safeName(v)+".tar.gz")
		if err := a.restoreVolumeArchive(r.Context(), v, file); err != nil {
			errorJSON(w, 502, "restore_failed", v+": "+err.Error())
			return
		}
	}
	if m.Project != "" {
		if _, err := a.projects.Deploy(m.Project); err != nil {
			errorJSON(w, 502, "restore_start_failed", err.Error())
			return
		}
	}
	a.db.AddAudit(a.currentActor(r), "backup.restore", m.Name, id)
	writeJSON(w, map[string]any{"ok": true, "backup": m})
}

func (a *App) backupImport(w http.ResponseWriter, r *http.Request) {
	mr, err := r.MultipartReader()
	if err != nil {
		errorJSON(w, 400, "backup_import_failed", "Backup-Datei fehlt: "+err.Error())
		return
	}
	if err := os.MkdirAll(a.backupsDir(), 0700); err != nil {
		errorJSON(w, 500, "backup_import_failed", err.Error())
		return
	}
	tmp, err := os.CreateTemp(a.backupsDir(), ".import-*.zip")
	if err != nil {
		errorJSON(w, 500, "backup_import_failed", err.Error())
		return
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	found := false
	for {
		part, e := mr.NextPart()
		if e == io.EOF {
			break
		}
		if e != nil {
			_ = tmp.Close()
			errorJSON(w, 400, "backup_import_failed", e.Error())
			return
		}
		if part.FormName() != "file" {
			part.Close()
			continue
		}
		found = true
		_, err = io.Copy(tmp, io.LimitReader(part, 200<<30))
		part.Close()
		break
	}
	if err := tmp.Close(); err != nil {
		errorJSON(w, 500, "backup_import_failed", err.Error())
		return
	}
	if !found || err != nil {
		errorJSON(w, 400, "backup_import_failed", "Backup-Datei fehlt")
		return
	}
	zr, err := zip.OpenReader(tmpName)
	if err != nil {
		errorJSON(w, 400, "backup_import_failed", "Ungültiges Backup-Archiv")
		return
	}
	defer zr.Close()
	var manifest backupManifest
	for _, f := range zr.File {
		if filepath.ToSlash(filepath.Clean(f.Name)) != "manifest.json" {
			continue
		}
		rc, e := f.Open()
		if e != nil {
			continue
		}
		b, e := io.ReadAll(io.LimitReader(rc, 1<<20))
		rc.Close()
		if e == nil {
			_ = json.Unmarshal(b, &manifest)
		}
		break
	}
	if manifest.Kind == "" || manifest.CreatedAt == 0 {
		errorJSON(w, 400, "backup_import_failed", "manifest.json fehlt oder ist ungültig")
		return
	}
	id := fmt.Sprintf("bkp_%d_%s", time.Now().Unix(), mustRandomHex(4))
	dst := filepath.Join(a.backupsDir(), id)
	if err := os.Mkdir(dst, 0700); err != nil {
		errorJSON(w, 500, "backup_import_failed", err.Error())
		return
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(dst)
		}
	}()
	for _, f := range zr.File {
		rel := filepath.ToSlash(filepath.Clean(f.Name))
		if rel == "." || rel == "" || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, "../") {
			errorJSON(w, 400, "backup_import_failed", "Unsicherer Pfad im Backup")
			return
		}
		if f.FileInfo().IsDir() {
			continue
		}
		out := filepath.Join(dst, filepath.FromSlash(rel))
		if !strings.HasPrefix(filepath.Clean(out)+string(os.PathSeparator), filepath.Clean(dst)+string(os.PathSeparator)) {
			errorJSON(w, 400, "backup_import_failed", "Unsicherer Pfad im Backup")
			return
		}
		if err := os.MkdirAll(filepath.Dir(out), 0700); err != nil {
			errorJSON(w, 500, "backup_import_failed", err.Error())
			return
		}
		rc, e := f.Open()
		if e != nil {
			errorJSON(w, 400, "backup_import_failed", e.Error())
			return
		}
		wf, e := os.OpenFile(out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if e != nil {
			rc.Close()
			errorJSON(w, 500, "backup_import_failed", e.Error())
			return
		}
		_, e = io.Copy(wf, rc)
		wf.Close()
		rc.Close()
		if e != nil {
			errorJSON(w, 500, "backup_import_failed", e.Error())
			return
		}
	}
	manifest.ID = id
	manifest.Name = strings.TrimSpace(manifest.Name)
	if manifest.Name == "" {
		manifest.Name = "Importiertes Backup"
	}
	manifest.Size = dirSize(dst)
	b, _ := json.MarshalIndent(manifest, "", "  ")
	if err := os.WriteFile(filepath.Join(dst, "manifest.json"), b, 0600); err != nil {
		errorJSON(w, 500, "backup_import_failed", err.Error())
		return
	}
	cleanup = false
	a.db.AddAudit(a.currentActor(r), "backup.import", manifest.Name, id)
	writeJSONStatus(w, http.StatusCreated, map[string]any{"ok": true, "backup": manifest})
}

func (a *App) backupDownload(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	dir, err := a.safeBackupDir(id)
	if err != nil {
		errorJSON(w, 400, "invalid_backup", err.Error())
		return
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	err = filepath.WalkDir(dir, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
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
		errorJSON(w, 500, "backup_error", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", "zentcontainer-backup-"+id+".zip"))
	w.Write(buf.Bytes())
}

func (a *App) safeBackupDir(id string) (string, error) {
	if id == "" || strings.Contains(id, "/") || strings.Contains(id, "\\") || strings.Contains(id, "..") {
		return "", errors.New("invalid backup id")
	}
	dir := filepath.Join(a.backupsDir(), id)
	if _, err := os.Stat(dir); err != nil {
		return "", err
	}
	return dir, nil
}

func (a *App) projectVolumes(ctx context.Context, project string) ([]string, error) {
	d, err := a.docker()
	if err != nil {
		return nil, err
	}
	cs, err := d.Containers(ctx, true)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	out := []string{}
	for _, c := range cs {
		if c.Labels["com.docker.compose.project"] != project {
			continue
		}
		for _, m := range c.Mounts {
			if m.Type == "volume" && m.Name != "" && !seen[m.Name] {
				seen[m.Name] = true
				out = append(out, m.Name)
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

func (a *App) restoreVolumeArchive(ctx context.Context, volume, file string) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	tarData, err := io.ReadAll(zr)
	_ = zr.Close()
	if err != nil {
		return err
	}
	if _, err := a.helperRun(ctx, volume, true, "fs", "clear", "/"); err != nil {
		return err
	}
	d, id, err := a.helperHold(ctx, volume, true)
	if err != nil {
		return err
	}
	defer d.ContainerRemove(context.Background(), id, true)
	_, err = d.RawBytes(ctx, http.MethodPut, "/containers/"+url.PathEscape(id)+"/archive?path="+url.QueryEscape("/mnt/volume"), "application/x-tar", bytes.NewReader(tarData))
	return err
}

func archiveProjectDir(root, name, dst string) error {
	dir := filepath.Join(root, name)
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	err = filepath.WalkDir(dir, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		rel, _ := filepath.Rel(dir, p)
		if rel == "." {
			return nil
		}
		if rel == ".history" || strings.HasPrefix(rel, ".history"+string(os.PathSeparator)) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		info, e := d.Info()
		if e != nil {
			return e
		}
		h, e := tar.FileInfoHeader(info, "")
		if e != nil {
			return e
		}
		h.Name = filepath.ToSlash(rel)
		if e = tw.WriteHeader(h); e != nil {
			return e
		}
		if info.Mode().IsRegular() {
			b, e := os.Open(p)
			if e != nil {
				return e
			}
			_, e = io.Copy(tw, b)
			_ = b.Close()
			return e
		}
		return nil
	})
	if e := tw.Close(); err == nil {
		err = e
	}
	if e := gz.Close(); err == nil {
		err = e
	}
	return err
}
func extractProjectArchive(src, root, name string) error {
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		clean := filepath.Clean(filepath.FromSlash(h.Name))
		if clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) || filepath.IsAbs(clean) {
			return errors.New("unsafe project archive")
		}
		target := filepath.Join(dir, clean)
		if h.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0700); err != nil {
				return err
			}
			continue
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		_, err = io.Copy(out, tr)
		_ = out.Close()
		if err != nil {
			return err
		}
	}
	return nil
}
func dirSize(dir string) int64 {
	var n int64
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, e error) error {
		if e == nil && !d.IsDir() {
			if i, x := d.Info(); x == nil {
				n += i.Size()
			}
		}
		return nil
	})
	return n
}

func mustRandomHex(n int) string {
	v, err := randomHex(n)
	if err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return v
}

// Keep dockerx imported even when build tags trim backup helpers in tests.
var _ = dockerx.Volume{}
