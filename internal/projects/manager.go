package projects

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type Manager struct{ Root string }

type Project struct {
	Name        string `json:"name"`
	Compose     string `json:"compose,omitempty"`
	Env         string `json:"env,omitempty"`
	Modified    int64  `json:"modified"`
	ComposeFile string `json:"compose_file,omitempty"`
	HasCompose  bool   `json:"has_compose"`
	FileCount   int    `json:"file_count"`
}

type Revision struct {
	ID      string `json:"id"`
	Created int64  `json:"created"`
	Compose string `json:"compose,omitempty"`
	Env     string `json:"env,omitempty"`
}

type FileEntry struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	IsDir    bool   `json:"is_dir"`
	Size     int64  `json:"size"`
	Modified int64  `json:"modified"`
}

type FileRevision struct {
	ID      string `json:"id"`
	Created int64  `json:"created"`
	Path    string `json:"path"`
	Action  string `json:"action"`
	Content string `json:"content,omitempty"`
}

type EnvVariable struct {
	Name       string `json:"name"`
	Default    string `json:"default,omitempty"`
	HasDefault bool   `json:"has_default"`
	Required   bool   `json:"required"`
	Set        bool   `json:"set"`
	Value      string `json:"value,omitempty"`
}

type EnvFileAnalysis struct {
	Path       string   `json:"path"`
	Used       []string `json:"used"`
	Unused     []string `json:"unused"`
	Missing    []string `json:"missing"`
	Duplicates []string `json:"duplicates"`
}

type ProjectAnalysis struct {
	ComposeFiles      []string            `json:"compose_files"`
	ComposeFile       string              `json:"compose_file,omitempty"`
	Variables         []EnvVariable       `json:"variables"`
	EnvFiles          []string            `json:"env_files"`
	EnvAnalysis       []EnvFileAnalysis   `json:"env_analysis"`
	ReferencedMissing []string            `json:"referenced_missing"`
	ServiceNames      []string            `json:"service_names"`
	Profiles          []string            `json:"profiles"`
	Dependencies      map[string][]string `json:"dependencies"`
	Secrets           []string            `json:"secrets"`
	Configs           []string            `json:"configs"`
}

type ProjectStatus struct {
	State       string   `json:"state"`
	ComposeFile string   `json:"compose_file,omitempty"`
	Services    int      `json:"services"`
	Running     int      `json:"running"`
	Names       []string `json:"names"`
	Detail      string   `json:"detail,omitempty"`
}

type projectMeta struct {
	ComposeFile string `json:"compose_file,omitempty"`
}

var validName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)
var envExpr = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:-|-|:\?|\?|:\+|\+)([^}]*))?\}`)
var simpleEnvExpr = regexp.MustCompile(`(^|[^$])\$([A-Za-z_][A-Za-z0-9_]*)`)
var serviceLine = regexp.MustCompile(`(?m)^\s{2}([A-Za-z0-9_.-]+):\s*(?:#.*)?$`)

func isTransientWorkspaceName(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	return strings.HasPrefix(n, ".smbdelete")
}

func New(root string) *Manager { return &Manager{Root: root} }

func (m *Manager) path(name string) (string, error) {
	if !validName.MatchString(name) {
		return "", errors.New("invalid project name")
	}
	return filepath.Join(m.Root, name), nil
}

func (m *Manager) Create(name string) error {
	dir, err := m.path(name)
	if err != nil {
		return err
	}
	if _, err := os.Stat(dir); err == nil {
		return errors.New("project already exists")
	}
	return os.MkdirAll(dir, 0700)
}

func (m *Manager) List() ([]Project, error) {
	ents, err := os.ReadDir(m.Root)
	if os.IsNotExist(err) {
		return []Project{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := []Project{}
	for _, e := range ents {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		p, err := m.projectSummary(e.Name())
		if err == nil {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out, nil
}

func (m *Manager) projectSummary(name string) (Project, error) {
	dir, err := m.path(name)
	if err != nil {
		return Project{}, err
	}
	st, err := os.Stat(dir)
	if err != nil {
		return Project{}, err
	}
	composeFiles, _ := m.composeFiles(name)
	selected, _ := m.selectedCompose(name, composeFiles)
	count := 0
	mod := st.ModTime().Unix()
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		if rel == ".history" || strings.HasPrefix(rel, ".history"+string(os.PathSeparator)) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if rel == ".zentcontainer.json" || isTransientWorkspaceName(d.Name()) {
			if d.IsDir() && isTransientWorkspaceName(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if rel != "." && !d.IsDir() {
			count++
			if x, _ := d.Info(); x != nil && x.ModTime().Unix() > mod {
				mod = x.ModTime().Unix()
			}
		}
		return nil
	})
	return Project{Name: name, Modified: mod, ComposeFile: selected, HasCompose: selected != "", FileCount: count}, nil
}

// Get remains backwards compatible for API clients from <=0.4 while projects no longer require compose.yaml.
func (m *Manager) Get(name string) (Project, error) {
	p, err := m.projectSummary(name)
	if err != nil {
		return Project{}, err
	}
	if p.ComposeFile != "" {
		b, _ := os.ReadFile(filepath.Join(m.Root, name, filepath.FromSlash(p.ComposeFile)))
		p.Compose = string(b)
	}
	if b, err := os.ReadFile(filepath.Join(m.Root, name, ".env")); err == nil {
		p.Env = string(b)
	}
	return p, nil
}

// Save remains backwards compatible and creates/updates compose.yaml + .env.
func (m *Manager) Save(name, compose, env string) error {
	dir, err := m.path(name)
	if err != nil {
		return err
	}
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	if strings.TrimSpace(compose) == "" {
		return errors.New("compose.yaml cannot be empty")
	}
	// Preserve the legacy whole-project revision stream for compatibility while
	// v0.5 additionally records per-file history.
	if old, err := os.ReadFile(filepath.Join(dir, "compose.yaml")); err == nil {
		oldEnv, _ := os.ReadFile(filepath.Join(dir, ".env"))
		if err := os.MkdirAll(filepath.Join(dir, ".history"), 0700); err == nil {
			stamp := time.Now().UTC().Format("20060102T150405.000000000Z")
			snapshot, _ := json.Marshal(Revision{ID: stamp, Created: time.Now().Unix(), Compose: string(old), Env: string(oldEnv)})
			_ = os.WriteFile(filepath.Join(dir, ".history", stamp+".json"), snapshot, 0600)
		}
	}
	if err := m.WriteFile(name, "compose.yaml", []byte(compose)); err != nil {
		return err
	}
	if err := m.WriteFile(name, ".env", []byte(env)); err != nil {
		return err
	}
	return m.SetComposeFile(name, "compose.yaml")
}

func (m *Manager) Delete(name string) error {
	dir, err := m.path(name)
	if err != nil {
		return err
	}
	return os.RemoveAll(dir)
}

func atomicWrite(path string, b []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func cleanProjectRel(p string) (string, error) {
	p = strings.TrimSpace(strings.ReplaceAll(p, "\\", "/"))
	p = strings.TrimPrefix(p, "/")
	if p == "" || p == "." {
		return "", nil
	}
	c := filepath.ToSlash(filepath.Clean(filepath.FromSlash(p)))
	if c == ".." || strings.HasPrefix(c, "../") || filepath.IsAbs(c) {
		return "", errors.New("invalid path")
	}
	if c == ".history" || strings.HasPrefix(c, ".history/") || c == ".zentcontainer.json" {
		return "", errors.New("reserved path")
	}
	return c, nil
}

func ensureNoSymlink(root, rel string, allowMissingLeaf bool) error {
	cur := root
	parts := strings.Split(filepath.FromSlash(rel), string(os.PathSeparator))
	for i, part := range parts {
		if part == "" || part == "." {
			continue
		}
		cur = filepath.Join(cur, part)
		st, err := os.Lstat(cur)
		if os.IsNotExist(err) && allowMissingLeaf && i == len(parts)-1 {
			return nil
		}
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return errors.New("symlinks are not allowed in project file operations")
		}
	}
	return nil
}

func (m *Manager) safePath(name, rel string, allowMissingLeaf bool) (string, string, error) {
	dir, err := m.path(name)
	if err != nil {
		return "", "", err
	}
	if _, err := os.Stat(dir); err != nil {
		return "", "", err
	}
	rel, err = cleanProjectRel(rel)
	if err != nil {
		return "", "", err
	}
	if err := ensureNoSymlink(dir, rel, allowMissingLeaf); err != nil {
		return "", "", err
	}
	return dir, filepath.Join(dir, filepath.FromSlash(rel)), nil
}

func (m *Manager) ListFiles(name, rel string) ([]FileEntry, error) {
	_, p, err := m.safePath(name, rel, false)
	if err != nil {
		return nil, err
	}
	ents, err := os.ReadDir(p)
	if err != nil {
		return nil, err
	}
	rel, _ = cleanProjectRel(rel)
	out := []FileEntry{}
	for _, e := range ents {
		if e.Name() == ".history" || e.Name() == ".zentcontainer.json" || isTransientWorkspaceName(e.Name()) {
			continue
		}
		if e.Type()&os.ModeSymlink != 0 {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		child := e.Name()
		if rel != "" {
			child = filepath.ToSlash(filepath.Join(rel, e.Name()))
		}
		out = append(out, FileEntry{Name: e.Name(), Path: child, IsDir: e.IsDir(), Size: info.Size(), Modified: info.ModTime().Unix()})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IsDir != out[j].IsDir {
			return out[i].IsDir
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out, nil
}

func (m *Manager) ReadFile(name, rel string) ([]byte, os.FileInfo, error) {
	_, p, err := m.safePath(name, rel, false)
	if err != nil {
		return nil, nil, err
	}
	st, err := os.Stat(p)
	if err != nil {
		return nil, nil, err
	}
	if st.IsDir() {
		return nil, nil, errors.New("path is a directory")
	}
	b, err := os.ReadFile(p)
	return b, st, err
}

func (m *Manager) WriteFile(name, rel string, b []byte) error {
	dir, p, err := m.safePath(name, rel, true)
	if err != nil {
		return err
	}
	if rel == "" {
		return errors.New("file path is required")
	}
	if old, err := os.ReadFile(p); err == nil {
		_ = m.snapshotFile(dir, rel, "write", old)
	}
	if st, err := os.Lstat(p); err == nil && st.IsDir() {
		return errors.New("path is a directory")
	}
	return atomicWrite(p, b, 0600)
}

func (m *Manager) Mkdir(name, rel string) error {
	_, p, err := m.safePath(name, rel, true)
	if err != nil {
		return err
	}
	if rel == "" {
		return errors.New("directory path is required")
	}
	return os.MkdirAll(p, 0700)
}

func (m *Manager) RemoveFile(name, rel string) error {
	dir, p, err := m.safePath(name, rel, false)
	if err != nil {
		return err
	}
	if rel == "" {
		return errors.New("cannot remove project root")
	}
	st, err := os.Stat(p)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		if old, err := os.ReadFile(p); err == nil {
			_ = m.snapshotFile(dir, rel, "delete", old)
		}
	}
	return os.RemoveAll(p)
}

func (m *Manager) Rename(name, from, to string) error {
	dir, src, err := m.safePath(name, from, false)
	if err != nil {
		return err
	}
	_, dst, err := m.safePath(name, to, true)
	if err != nil {
		return err
	}
	if from == "" || to == "" {
		return errors.New("source and target are required")
	}
	if old, err := os.ReadFile(src); err == nil {
		_ = m.snapshotFile(dir, from, "rename", old)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		return err
	}
	return os.Rename(src, dst)
}

func (m *Manager) snapshotFile(dir, rel, action string, b []byte) error {
	h := filepath.Join(dir, ".history", "files")
	if err := os.MkdirAll(h, 0700); err != nil {
		return err
	}
	stamp := time.Now().UTC().Format("20060102T150405.000000000Z")
	sum := sha256.Sum256([]byte(rel + stamp))
	id := stamp + "-" + fmt.Sprintf("%x", sum[:4])
	rec := FileRevision{ID: id, Created: time.Now().Unix(), Path: filepath.ToSlash(rel), Action: action, Content: base64.StdEncoding.EncodeToString(b)}
	raw, _ := json.Marshal(rec)
	return os.WriteFile(filepath.Join(h, id+".json"), raw, 0600)
}

func (m *Manager) ListFileRevisions(name string) ([]FileRevision, error) {
	dir, err := m.path(name)
	if err != nil {
		return nil, err
	}
	h := filepath.Join(dir, ".history", "files")
	ents, err := os.ReadDir(h)
	if os.IsNotExist(err) {
		return []FileRevision{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := []FileRevision{}
	for _, e := range ents {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(h, e.Name()))
		if err != nil {
			continue
		}
		var r FileRevision
		if json.Unmarshal(b, &r) == nil {
			r.Content = ""
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	if len(out) > 100 {
		out = out[:100]
	}
	return out, nil
}

func (m *Manager) GetFileRevision(name, id string) (FileRevision, error) {
	if !validRevisionID(id) {
		return FileRevision{}, errors.New("invalid revision id")
	}
	dir, err := m.path(name)
	if err != nil {
		return FileRevision{}, err
	}
	b, err := os.ReadFile(filepath.Join(dir, ".history", "files", id+".json"))
	if err != nil {
		return FileRevision{}, err
	}
	var r FileRevision
	if err := json.Unmarshal(b, &r); err != nil {
		return FileRevision{}, err
	}
	return r, nil
}

func (m *Manager) RestoreFileRevision(name, id string) error {
	r, err := m.GetFileRevision(name, id)
	if err != nil {
		return err
	}
	b, err := base64.StdEncoding.DecodeString(r.Content)
	if err != nil {
		return err
	}
	return m.WriteFile(name, r.Path, b)
}

func (m *Manager) meta(name string) (projectMeta, error) {
	dir, err := m.path(name)
	if err != nil {
		return projectMeta{}, err
	}
	b, err := os.ReadFile(filepath.Join(dir, ".zentcontainer.json"))
	if os.IsNotExist(err) {
		return projectMeta{}, nil
	}
	if err != nil {
		return projectMeta{}, err
	}
	var x projectMeta
	if err := json.Unmarshal(b, &x); err != nil {
		return projectMeta{}, nil
	}
	return x, nil
}
func (m *Manager) writeMeta(name string, x projectMeta) error {
	dir, err := m.path(name)
	if err != nil {
		return err
	}
	b, _ := json.MarshalIndent(x, "", "  ")
	return atomicWrite(filepath.Join(dir, ".zentcontainer.json"), b, 0600)
}

func isComposeName(n string) bool {
	n = strings.ToLower(filepath.Base(n))
	return n == "compose.yaml" || n == "compose.yml" || n == "docker-compose.yaml" || n == "docker-compose.yml" || strings.HasPrefix(n, "compose.") && (strings.HasSuffix(n, ".yaml") || strings.HasSuffix(n, ".yml"))
}
func (m *Manager) composeFiles(name string) ([]string, error) {
	dir, err := m.path(name)
	if err != nil {
		return nil, err
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, e := range ents {
		if !e.IsDir() && isComposeName(e.Name()) {
			out = append(out, e.Name())
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return composeRank(out[i]) < composeRank(out[j]) })
	return out, nil
}
func composeRank(n string) int {
	switch strings.ToLower(n) {
	case "compose.yaml":
		return 0
	case "compose.yml":
		return 1
	case "docker-compose.yaml":
		return 2
	case "docker-compose.yml":
		return 3
	}
	return 10
}
func (m *Manager) selectedCompose(name string, files []string) (string, error) {
	if len(files) == 0 {
		return "", nil
	}
	meta, _ := m.meta(name)
	for _, x := range files {
		if x == meta.ComposeFile {
			return x, nil
		}
	}
	return files[0], nil
}
func (m *Manager) SetComposeFile(name, file string) error {
	file, err := cleanProjectRel(file)
	if err != nil {
		return err
	}
	if file == "" {
		return m.writeMeta(name, projectMeta{})
	}
	files, err := m.composeFiles(name)
	if err != nil {
		return err
	}
	found := false
	for _, x := range files {
		if x == file {
			found = true
		}
	}
	if !found {
		return errors.New("compose file not found")
	}
	return m.writeMeta(name, projectMeta{ComposeFile: file})
}

func parseEnv(text string) (map[string]string, []string) {
	vals := map[string]string{}
	seen := map[string]bool{}
	dups := []string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		}
		i := strings.Index(line, "=")
		if i < 1 {
			continue
		}
		k := strings.TrimSpace(line[:i])
		if !regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString(k) {
			continue
		}
		v := strings.TrimSpace(line[i+1:])
		if seen[k] {
			dups = append(dups, k)
		}
		seen[k] = true
		vals[k] = strings.Trim(v, "\"'")
	}
	sort.Strings(dups)
	return vals, dups
}

func (m *Manager) Analyze(name string) (ProjectAnalysis, error) {
	dir, err := m.path(name)
	if err != nil {
		return ProjectAnalysis{}, err
	}
	files, err := m.composeFiles(name)
	if err != nil {
		return ProjectAnalysis{}, err
	}
	selected, _ := m.selectedCompose(name, files)
	a := ProjectAnalysis{ComposeFiles: files, ComposeFile: selected, Variables: []EnvVariable{}, EnvFiles: []string{}, EnvAnalysis: []EnvFileAnalysis{}, ReferencedMissing: []string{}, ServiceNames: []string{}, Profiles: []string{}, Dependencies: map[string][]string{}, Secrets: []string{}, Configs: []string{}}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if isTransientWorkspaceName(e.Name()) {
			continue
		}
		if !e.IsDir() && strings.HasPrefix(e.Name(), ".env") {
			a.EnvFiles = append(a.EnvFiles, e.Name())
		}
	}
	sort.Strings(a.EnvFiles)
	if selected == "" {
		return a, nil
	}
	raw, err := os.ReadFile(filepath.Join(dir, selected))
	if err != nil {
		return a, err
	}
	text := string(raw)
	vars := map[string]*EnvVariable{}
	for _, x := range envExpr.FindAllStringSubmatch(text, -1) {
		v := vars[x[1]]
		if v == nil {
			v = &EnvVariable{Name: x[1]}
			vars[x[1]] = v
		}
		if len(x) > 2 && (x[2] == ":-" || x[2] == "-") {
			v.HasDefault = true
			if len(x) > 3 {
				v.Default = x[3]
			}
		}
		if len(x) > 2 && (x[2] == "?" || x[2] == ":?") {
			v.Required = true
		}
	}
	for _, x := range simpleEnvExpr.FindAllStringSubmatch(text, -1) {
		if vars[x[2]] == nil {
			vars[x[2]] = &EnvVariable{Name: x[2]}
		}
	}
	envVals := map[string]map[string]string{}
	for _, ef := range a.EnvFiles {
		b, _ := os.ReadFile(filepath.Join(dir, ef))
		vals, dups := parseEnv(string(b))
		envVals[ef] = vals
		ea := EnvFileAnalysis{Path: ef, Used: []string{}, Unused: []string{}, Missing: []string{}, Duplicates: dups}
		for k := range vals {
			if vars[k] != nil {
				ea.Used = append(ea.Used, k)
			} else {
				ea.Unused = append(ea.Unused, k)
			}
		}
		for k := range vars {
			if _, ok := vals[k]; !ok {
				ea.Missing = append(ea.Missing, k)
			}
		}
		sort.Strings(ea.Used)
		sort.Strings(ea.Unused)
		sort.Strings(ea.Missing)
		a.EnvAnalysis = append(a.EnvAnalysis, ea)
	}
	primary := envVals[".env"]
	names := make([]string, 0, len(vars))
	for k := range vars {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		v := *vars[k]
		if primary != nil {
			v.Value, v.Set = primary[k]
		}
		a.Variables = append(a.Variables, v)
	}
	// Lightweight service discovery for the common Compose shape; docker compose config remains the final validator.
	inServices := false
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "services:" {
			inServices = true
			continue
		}
		if inServices {
			if len(line) > 0 && line[0] != ' ' && strings.TrimSpace(line) != "" {
				break
			}
			if x := serviceLine.FindStringSubmatch(line); len(x) > 1 {
				a.ServiceNames = append(a.ServiceNames, x[1])
			}
		}
	}
	// Highlight common local file references without pretending to be a full YAML parser.
	refs := regexp.MustCompile(`(?:^|[\s\-])(?:\./)?([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+|\.env[A-Za-z0-9_.-]*)`).FindAllStringSubmatch(text, -1)
	seen := map[string]bool{}
	for _, r := range refs {
		rel := strings.TrimPrefix(r[1], "./")
		if rel == "" || seen[rel] {
			continue
		}
		seen[rel] = true
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(rel))); os.IsNotExist(err) {
			a.ReferencedMissing = append(a.ReferencedMissing, rel)
		}
	}
	sort.Strings(a.ReferencedMissing)
	if cfg, err := m.run(name, "config", "--format", "json"); err == nil {
		var root map[string]any
		if json.Unmarshal([]byte(cfg), &root) == nil {
			profiles := map[string]bool{}
			if svcs, ok := root["services"].(map[string]any); ok {
				for svc, rawSvc := range svcs {
					m, _ := rawSvc.(map[string]any)
					if ps, ok := m["profiles"].([]any); ok {
						for _, p := range ps {
							if x := strings.TrimSpace(fmt.Sprint(p)); x != "" {
								profiles[x] = true
							}
						}
					}
					deps := []string{}
					switch d := m["depends_on"].(type) {
					case map[string]any:
						for k := range d {
							deps = append(deps, k)
						}
					case []any:
						for _, v := range d {
							deps = append(deps, fmt.Sprint(v))
						}
					}
					sort.Strings(deps)
					if len(deps) > 0 {
						a.Dependencies[svc] = deps
					}
				}
			}
			for p := range profiles {
				a.Profiles = append(a.Profiles, p)
			}
			sort.Strings(a.Profiles)
			for _, key := range []string{"secrets", "configs"} {
				if mm, ok := root[key].(map[string]any); ok {
					names := []string{}
					for k := range mm {
						names = append(names, k)
					}
					sort.Strings(names)
					if key == "secrets" {
						a.Secrets = names
					} else {
						a.Configs = names
					}
				}
			}
		}
	}
	return a, nil
}

func (m *Manager) run(name string, args ...string) (string, error) {
	dir, err := m.path(name)
	if err != nil {
		return "", err
	}
	files, err := m.composeFiles(name)
	if err != nil {
		return "", err
	}
	compose, err := m.selectedCompose(name, files)
	if err != nil {
		return "", err
	}
	if compose == "" {
		return "", errors.New("no compose file found")
	}
	base := []string{"compose", "-p", name, "-f", filepath.Join(dir, compose)}
	if _, err := os.Stat(filepath.Join(dir, ".env")); err == nil {
		base = append(base, "--env-file", filepath.Join(dir, ".env"))
	}
	base = append(base, args...)
	cmd := exec.Command("docker", base...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), errors.New(strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
func (m *Manager) Validate(name string) (string, error) { return m.run(name, "config", "--quiet") }
func (m *Manager) ValidateContent(name, compose, env string) (string, error) {
	if !validName.MatchString(name) {
		return "", errors.New("invalid project name")
	}
	if strings.TrimSpace(compose) == "" {
		return "", errors.New("compose.yaml cannot be empty")
	}
	tmp, err := os.MkdirTemp(m.Root, ".validate-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)
	composePath := filepath.Join(tmp, "compose.yaml")
	envPath := filepath.Join(tmp, ".env")
	if err := os.WriteFile(composePath, []byte(compose), 0600); err != nil {
		return "", err
	}
	if err := os.WriteFile(envPath, []byte(env), 0600); err != nil {
		return "", err
	}
	cmd := exec.Command("docker", "compose", "-p", name, "-f", composePath, "--env-file", envPath, "config", "--quiet")
	cmd.Dir = tmp
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), errors.New(strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
func (m *Manager) Config(name string) (string, error) { return m.run(name, "config") }
func (m *Manager) Deploy(name string) (string, error) { return m.run(name, "up", "-d") }

func (m *Manager) DeployProfiles(name string, profiles []string) (string, error) {
	dir, err := m.path(name)
	if err != nil {
		return "", err
	}
	files, err := m.composeFiles(name)
	if err != nil {
		return "", err
	}
	compose, err := m.selectedCompose(name, files)
	if err != nil {
		return "", err
	}
	if compose == "" {
		return "", errors.New("no compose file found")
	}
	base := []string{"compose", "-p", name, "-f", filepath.Join(dir, compose)}
	if _, err := os.Stat(filepath.Join(dir, ".env")); err == nil {
		base = append(base, "--env-file", filepath.Join(dir, ".env"))
	}
	seen := map[string]bool{}
	for _, p := range profiles {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		base = append(base, "--profile", p)
	}
	base = append(base, "up", "-d")
	cmd := exec.Command("docker", base...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), errors.New(strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func (m *Manager) Down(name string) (string, error)    { return m.run(name, "down") }
func (m *Manager) Stop(name string) (string, error)    { return m.run(name, "stop") }
func (m *Manager) Start(name string) (string, error)   { return m.run(name, "start") }
func (m *Manager) Restart(name string) (string, error) { return m.run(name, "restart") }
func (m *Manager) Pull(name string) (string, error)    { return m.run(name, "pull") }
func (m *Manager) Update(name string) (string, error) {
	pull, err := m.Pull(name)
	if err != nil {
		return pull, err
	}
	up, err := m.Deploy(name)
	if pull != "" && up != "" {
		return pull + "\n" + up, err
	}
	return pull + up, err
}
func (m *Manager) Logs(name string, tail int) (string, error) {
	if tail <= 0 {
		tail = 200
	}
	return m.run(name, "logs", "--no-color", "--tail", strconvI(tail))
}

func (m *Manager) Build(name, tag, dockerfile, contextDir string) (string, error) {
	dir, err := m.path(name)
	if err != nil {
		return "", err
	}
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return "", errors.New("image tag is required")
	}
	dockerfile, err = cleanProjectRel(dockerfile)
	if err != nil {
		return "", err
	}
	if dockerfile == "" {
		dockerfile = "Dockerfile"
	}
	contextDir, err = cleanProjectRel(contextDir)
	if err != nil {
		return "", err
	}
	df := filepath.Join(dir, filepath.FromSlash(dockerfile))
	if _, err := os.Stat(df); err != nil {
		return "", errors.New("Dockerfile not found: " + dockerfile)
	}
	ctx := dir
	if contextDir != "" {
		ctx = filepath.Join(dir, filepath.FromSlash(contextDir))
		st, e := os.Stat(ctx)
		if e != nil || !st.IsDir() {
			return "", errors.New("build context not found")
		}
	}
	cmd := exec.Command("docker", "build", "--progress=plain", "-f", df, "-t", tag, ctx)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), errors.New(strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func (m *Manager) Status(name string) (ProjectStatus, error) {
	files, err := m.composeFiles(name)
	if err != nil {
		return ProjectStatus{}, err
	}
	compose, _ := m.selectedCompose(name, files)
	if compose == "" {
		return ProjectStatus{State: "no_compose", Names: []string{}}, nil
	}
	out, err := m.run(name, "ps", "--format", "json")
	if err != nil {
		low := strings.ToLower(err.Error())
		if strings.Contains(low, "no such") || strings.Contains(low, "not found") {
			return ProjectStatus{State: "stopped", ComposeFile: compose, Names: []string{}}, nil
		}
		return ProjectStatus{State: "error", ComposeFile: compose, Detail: err.Error(), Names: []string{}}, nil
	}
	s := ProjectStatus{State: "stopped", ComposeFile: compose, Names: []string{}}
	text := strings.TrimSpace(out)
	if text == "" {
		return s, nil
	}
	var rows []map[string]any
	if strings.HasPrefix(text, "[") {
		_ = json.Unmarshal([]byte(text), &rows)
	} else {
		for _, line := range strings.Split(text, "\n") {
			var row map[string]any
			if json.Unmarshal([]byte(line), &row) == nil {
				rows = append(rows, row)
			}
		}
	}
	s.Services = len(rows)
	for _, r := range rows {
		name := fmt.Sprint(r["Service"])
		if name == "<nil>" || name == "" {
			name = fmt.Sprint(r["Name"])
		}
		if name != "" && name != "<nil>" {
			s.Names = append(s.Names, name)
		}
		state := strings.ToLower(fmt.Sprint(r["State"]))
		if strings.Contains(state, "running") {
			s.Running++
		}
	}
	if s.Services == 0 {
		s.State = "stopped"
	} else if s.Running == s.Services {
		s.State = "running"
	} else if s.Running > 0 {
		s.State = "partial"
	} else {
		s.State = "stopped"
	}
	return s, nil
}

func strconvI(i int) string {
	const digits = "0123456789"
	if i == 0 {
		return "0"
	}
	var b [20]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = digits[i%10]
		i /= 10
	}
	return string(b[n:])
}

func (m *Manager) revisionDir(name string) (string, error) {
	dir, err := m.path(name)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, ".history"), nil
}
func validRevisionID(id string) bool {
	if id == "" || strings.Contains(id, "/") || strings.Contains(id, "\\") || strings.Contains(id, "..") {
		return false
	}
	for _, r := range id {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '.' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}
func (m *Manager) ListRevisions(name string) ([]Revision, error) {
	h, err := m.revisionDir(name)
	if err != nil {
		return nil, err
	}
	ents, err := os.ReadDir(h)
	if os.IsNotExist(err) {
		return []Revision{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := []Revision{}
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		ext := filepath.Ext(e.Name())
		if ext != ".json" && ext != ".yaml" {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ext)
		st, _ := e.Info()
		created := int64(0)
		if st != nil {
			created = st.ModTime().Unix()
		}
		out = append(out, Revision{ID: id, Created: created})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out, nil
}
func (m *Manager) GetRevision(name, id string) (Revision, error) {
	if !validRevisionID(id) {
		return Revision{}, errors.New("invalid revision id")
	}
	h, err := m.revisionDir(name)
	if err != nil {
		return Revision{}, err
	}
	if b, err := os.ReadFile(filepath.Join(h, id+".json")); err == nil {
		var v Revision
		if json.Unmarshal(b, &v) != nil {
			return Revision{}, errors.New("invalid revision")
		}
		if v.ID == "" {
			v.ID = id
		}
		return v, nil
	}
	b, err := os.ReadFile(filepath.Join(h, id+".yaml"))
	if err != nil {
		return Revision{}, err
	}
	st, _ := os.Stat(filepath.Join(h, id+".yaml"))
	v := Revision{ID: id, Compose: string(b)}
	if st != nil {
		v.Created = st.ModTime().Unix()
	}
	return v, nil
}
func (m *Manager) RestoreRevision(name, id string) (Revision, error) {
	v, err := m.GetRevision(name, id)
	if err != nil {
		return Revision{}, err
	}
	if err := m.Save(name, v.Compose, v.Env); err != nil {
		return Revision{}, err
	}
	return v, nil
}
