package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Store struct {
	Path string
	mu   sync.Mutex
}

type User struct {
	ID           int64  `json:"id"`
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
	IsAdmin      bool   `json:"is_admin"`
	Language     string `json:"language"`
}
type Session struct {
	TokenHash string `json:"token_hash"`
	UserID    int64  `json:"user_id"`
	ExpiresAt int64  `json:"expires_at"`
}
type APIKey struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	Prefix     string `json:"prefix"`
	SecretHash string `json:"secret_hash"`
	Scopes     string `json:"scopes"`
	CreatedAt  int64  `json:"created_at"`
	LastUsedAt int64  `json:"last_used_at"`
}
type Audit struct {
	ID       int64  `json:"id"`
	At       int64  `json:"at"`
	Actor    string `json:"actor"`
	Action   string `json:"action"`
	Resource string `json:"resource"`
	Detail   string `json:"detail"`
}
type Agent struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	URL        string `json:"url"`
	ServerCert string `json:"server_cert"`
	Version    string `json:"version"`
	CreatedAt  int64  `json:"created_at"`
	LastSeenAt int64  `json:"last_seen_at"`
}
type UpdateCheck struct {
	ResourceID    string `json:"resource_id"`
	ImageRef      string `json:"image_ref"`
	CurrentDigest string `json:"current_digest"`
	RemoteDigest  string `json:"remote_digest"`
	Status        string `json:"status"`
	CheckedAt     int64  `json:"checked_at"`
}
type Registry struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Server    string `json:"server"`
	Username  string `json:"username"`
	SecretEnc string `json:"-"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
}
type PendingContainerEdit struct {
	Name      string `json:"name"`
	Payload   string `json:"payload"`
	UpdatedAt int64  `json:"updated_at"`
}
type ContainerGroup struct {
	ID        int64                  `json:"id"`
	Name      string                 `json:"name"`
	CreatedAt int64                  `json:"created_at"`
	UpdatedAt int64                  `json:"updated_at"`
	Members   []ContainerGroupMember `json:"members"`
}
type ContainerGroupMember struct {
	GroupID       int64  `json:"group_id,omitempty"`
	HostID        string `json:"host_id"`
	ContainerName string `json:"container_name"`
}

func Open(path string) (*Store, error) {
	if _, err := exec.LookPath("sqlite3"); err != nil {
		return nil, errors.New("sqlite3 executable is required")
	}
	if err := os.MkdirAll(filepathDir(path), 0700); err != nil {
		return nil, err
	}
	s := &Store{Path: path}
	if err := s.init(); err != nil {
		return nil, err
	}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	if err := s.hardenFileModes(); err != nil {
		return nil, err
	}
	return s, nil
}

func filepathDir(p string) string {
	i := strings.LastIndexByte(p, '/')
	if i <= 0 {
		return "."
	}
	return p[:i]
}
func q(v string) string { return "'" + strings.ReplaceAll(v, "'", "''") + "'" }
func b(v bool) int {
	if v {
		return 1
	}
	return 0
}

func (s *Store) run(sql string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cmd := exec.Command("sqlite3", "-cmd", ".timeout 5000", "-cmd", "PRAGMA foreign_keys=ON", "-json", s.Path, sql)
	out, err := cmd.CombinedOutput()
	modeErr := s.hardenFileModes()
	if err != nil {
		return nil, fmt.Errorf("sqlite: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if modeErr != nil {
		return nil, modeErr
	}
	return out, nil
}
func (s *Store) exec(sql string) error { _, err := s.run(sql); return err }

func (s *Store) hardenFileModes() error {
	if err := os.Chmod(filepathDir(s.Path), 0700); err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, path := range []string{s.Path, s.Path + "-wal", s.Path + "-shm"} {
		if err := os.Chmod(path, 0600); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func (s *Store) init() error {
	schema := `PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT NOT NULL UNIQUE,password_hash TEXT NOT NULL,is_admin INTEGER NOT NULL DEFAULT 0,language TEXT NOT NULL DEFAULT 'de',created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL,expires_at INTEGER NOT NULL,created_at INTEGER NOT NULL,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS api_keys(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,prefix TEXT NOT NULL UNIQUE,secret_hash TEXT NOT NULL,scopes TEXT NOT NULL,created_at INTEGER NOT NULL,last_used_at INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY AUTOINCREMENT,at INTEGER NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,resource TEXT NOT NULL,detail TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS projects(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL UNIQUE,path TEXT NOT NULL,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS project_revisions(id INTEGER PRIMARY KEY AUTOINCREMENT,project_id INTEGER NOT NULL,revision INTEGER NOT NULL,content TEXT NOT NULL,created_at INTEGER NOT NULL,FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS update_checks(resource_id TEXT PRIMARY KEY,image_ref TEXT NOT NULL,current_digest TEXT NOT NULL,remote_digest TEXT NOT NULL,status TEXT NOT NULL,checked_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS agents(id TEXT PRIMARY KEY,name TEXT NOT NULL,url TEXT NOT NULL UNIQUE,server_cert TEXT NOT NULL,version TEXT NOT NULL DEFAULT '',created_at INTEGER NOT NULL,last_seen_at INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS registries(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,server TEXT NOT NULL UNIQUE,username TEXT NOT NULL DEFAULT '',secret_enc TEXT NOT NULL DEFAULT '',created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS adopted_containers(name TEXT PRIMARY KEY,adopted_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS pending_container_edits(name TEXT PRIMARY KEY,payload TEXT NOT NULL,updated_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS container_groups(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL COLLATE NOCASE UNIQUE,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS container_group_members(group_id INTEGER NOT NULL,host_id TEXT NOT NULL,container_name TEXT NOT NULL,PRIMARY KEY(group_id,host_id,container_name),FOREIGN KEY(group_id) REFERENCES container_groups(id) ON DELETE CASCADE);
`
	return s.exec(schema)
}

func (s *Store) migrate() error {
	out, err := s.run("PRAGMA table_info(users);")
	if err != nil {
		return err
	}
	var rows []map[string]any
	if len(out) > 0 {
		if err := json.Unmarshal(out, &rows); err != nil {
			return err
		}
	}
	for _, row := range rows {
		if name, _ := row["name"].(string); name == "language" {
			return nil
		}
	}
	return s.exec("ALTER TABLE users ADD COLUMN language TEXT NOT NULL DEFAULT 'de';")
}

func normalizeLanguage(v string) string {
	if strings.EqualFold(strings.TrimSpace(v), "en") {
		return "en"
	}
	return "de"
}

func (s *Store) GetSetting(key string) (string, bool, error) {
	out, err := s.run("SELECT value FROM settings WHERE key=" + q(key) + " LIMIT 1;")
	if err != nil {
		return "", false, err
	}
	var rows []map[string]any
	if len(out) == 0 {
		return "", false, nil
	}
	if err := json.Unmarshal(out, &rows); err != nil {
		return "", false, err
	}
	if len(rows) == 0 {
		return "", false, nil
	}
	v, _ := rows[0]["value"].(string)
	return v, true, nil
}
func (s *Store) SetSetting(key, val string) error {
	return s.exec("INSERT INTO settings(key,value) VALUES(" + q(key) + "," + q(val) + ") ON CONFLICT(key) DO UPDATE SET value=excluded.value;")
}

func (s *Store) SetSettings(values map[string]string) error {
	if len(values) == 0 {
		return nil
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var sql strings.Builder
	sql.WriteString("BEGIN IMMEDIATE;")
	for _, key := range keys {
		sql.WriteString("INSERT INTO settings(key,value) VALUES(")
		sql.WriteString(q(key))
		sql.WriteByte(',')
		sql.WriteString(q(values[key]))
		sql.WriteString(") ON CONFLICT(key) DO UPDATE SET value=excluded.value;")
	}
	sql.WriteString("COMMIT;")
	return s.exec(sql.String())
}
func (s *Store) IsSetup() bool { _, ok, _ := s.GetSetting("role"); return ok }
func (s *Store) Role() string  { v, _, _ := s.GetSetting("role"); return v }

func (s *Store) CreateUser(username, hash string, admin bool) (int64, error) {
	return s.CreateUserWithLanguage(username, hash, admin, "de")
}
func (s *Store) CreateUserWithLanguage(username, hash string, admin bool, language string) (int64, error) {
	now := time.Now().Unix()
	language = normalizeLanguage(language)
	if err := s.exec(fmt.Sprintf("INSERT INTO users(username,password_hash,is_admin,language,created_at) VALUES(%s,%s,%d,%s,%d);", q(username), q(hash), b(admin), q(language), now)); err != nil {
		return 0, err
	}
	u, ok, err := s.UserByName(username)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, errors.New("created user not found")
	}
	return u.ID, nil
}
func (s *Store) UserByName(username string) (User, bool, error) {
	out, err := s.run("SELECT id,username,password_hash,is_admin,language FROM users WHERE username=" + q(username) + " LIMIT 1;")
	if err != nil {
		return User{}, false, err
	}
	var raw []struct {
		ID           int64  `json:"id"`
		Username     string `json:"username"`
		PasswordHash string `json:"password_hash"`
		IsAdmin      int    `json:"is_admin"`
		Language     string `json:"language"`
	}
	if len(out) == 0 {
		return User{}, false, nil
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return User{}, false, err
	}
	if len(raw) == 0 {
		return User{}, false, nil
	}
	return User{ID: raw[0].ID, Username: raw[0].Username, PasswordHash: raw[0].PasswordHash, IsAdmin: raw[0].IsAdmin == 1, Language: normalizeLanguage(raw[0].Language)}, true, nil
}
func (s *Store) UserByID(id int64) (User, bool, error) {
	out, err := s.run("SELECT id,username,password_hash,is_admin,language FROM users WHERE id=" + strconv.FormatInt(id, 10) + " LIMIT 1;")
	if err != nil {
		return User{}, false, err
	}
	var rows []map[string]any
	if len(out) == 0 {
		return User{}, false, nil
	}
	if err := json.Unmarshal(out, &rows); err != nil {
		return User{}, false, err
	}
	if len(rows) == 0 {
		return User{}, false, nil
	}
	r := rows[0]
	lang, _ := r["language"].(string)
	return User{ID: int64(r["id"].(float64)), Username: r["username"].(string), PasswordHash: r["password_hash"].(string), IsAdmin: int(r["is_admin"].(float64)) == 1, Language: normalizeLanguage(lang)}, true, nil
}

func (s *Store) UpdateUserLanguage(userID int64, language string) error {
	return s.exec("UPDATE users SET language=" + q(normalizeLanguage(language)) + " WHERE id=" + strconv.FormatInt(userID, 10) + ";")
}

func (s *Store) UpdateUserPasswordHash(userID int64, hash string) error {
	return s.exec("UPDATE users SET password_hash=" + q(hash) + " WHERE id=" + strconv.FormatInt(userID, 10) + ";")
}

func (s *Store) ChangeUserPassword(userID int64, hash, keepSessionHash string) error {
	return s.exec("BEGIN IMMEDIATE; UPDATE users SET password_hash=" + q(hash) + " WHERE id=" + strconv.FormatInt(userID, 10) + "; DELETE FROM sessions WHERE user_id=" + strconv.FormatInt(userID, 10) + " AND token_hash<>" + q(keepSessionHash) + "; COMMIT;")
}

func (s *Store) DeleteUser(id int64) error {
	return s.exec("DELETE FROM users WHERE id=" + strconv.FormatInt(id, 10) + ";")
}

func (s *Store) CreateSession(hash string, userID int64, expires int64) error {
	return s.exec(fmt.Sprintf("INSERT INTO sessions(token_hash,user_id,expires_at,created_at) VALUES(%s,%d,%d,%d);", q(hash), userID, expires, time.Now().Unix()))
}
func (s *Store) SessionUser(hash string) (User, bool, error) {
	u, _, ok, err := s.SessionUserWithExpiry(hash)
	return u, ok, err
}
func (s *Store) SessionUserWithExpiry(hash string) (User, int64, bool, error) {
	out, err := s.run(fmt.Sprintf("SELECT u.id,u.username,u.password_hash,u.is_admin,u.language,s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=%s AND s.expires_at>%d LIMIT 1;", q(hash), time.Now().Unix()))
	if err != nil {
		return User{}, 0, false, err
	}
	var rows []map[string]any
	if len(out) == 0 {
		return User{}, 0, false, nil
	}
	if err := json.Unmarshal(out, &rows); err != nil {
		return User{}, 0, false, err
	}
	if len(rows) == 0 {
		return User{}, 0, false, nil
	}
	r := rows[0]
	lang, _ := r["language"].(string)
	u := User{ID: int64(r["id"].(float64)), Username: r["username"].(string), PasswordHash: r["password_hash"].(string), IsAdmin: int(r["is_admin"].(float64)) == 1, Language: normalizeLanguage(lang)}
	return u, int64(r["expires_at"].(float64)), true, nil
}
func (s *Store) ExtendSession(hash string, expires int64) error {
	return s.exec(fmt.Sprintf("UPDATE sessions SET expires_at=%d WHERE token_hash=%s;", expires, q(hash)))
}
func (s *Store) DeleteSession(hash string) error {
	return s.exec("DELETE FROM sessions WHERE token_hash=" + q(hash) + ";")
}
func (s *Store) CleanupSessions() error {
	return s.exec(fmt.Sprintf("DELETE FROM sessions WHERE expires_at<=%d;", time.Now().Unix()))
}

func (s *Store) AddAudit(actor, action, resource, detail string) {
	_ = s.exec(fmt.Sprintf("INSERT INTO audit_log(at,actor,action,resource,detail) VALUES(%d,%s,%s,%s,%s);", time.Now().Unix(), q(actor), q(action), q(resource), q(detail)))
}
func (s *Store) AuditList(limit int) ([]Audit, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	out, err := s.run(fmt.Sprintf("SELECT id,at,actor,action,resource,detail FROM audit_log ORDER BY id DESC LIMIT %d;", limit))
	if err != nil {
		return nil, err
	}
	v := []Audit{}
	if len(out) == 0 {
		return v, nil
	}
	return v, json.Unmarshal(out, &v)
}

func (s *Store) UpsertPendingContainerEdit(name, payload string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("container name is required")
	}
	return s.exec(fmt.Sprintf(`INSERT INTO pending_container_edits(name,payload,updated_at) VALUES(%s,%s,%d)
ON CONFLICT(name) DO UPDATE SET payload=excluded.payload,updated_at=excluded.updated_at;`, q(name), q(payload), time.Now().Unix()))
}

func (s *Store) PendingContainerEdit(name string) (PendingContainerEdit, bool, error) {
	out, err := s.run("SELECT name,payload,updated_at FROM pending_container_edits WHERE name=" + q(strings.TrimSpace(name)) + " LIMIT 1;")
	if err != nil {
		return PendingContainerEdit{}, false, err
	}
	var rows []PendingContainerEdit
	if len(out) == 0 {
		return PendingContainerEdit{}, false, nil
	}
	if err := json.Unmarshal(out, &rows); err != nil {
		return PendingContainerEdit{}, false, err
	}
	if len(rows) == 0 {
		return PendingContainerEdit{}, false, nil
	}
	return rows[0], true, nil
}

func (s *Store) ListPendingContainerEdits() ([]PendingContainerEdit, error) {
	out, err := s.run("SELECT name,payload,updated_at FROM pending_container_edits ORDER BY name;")
	if err != nil {
		return nil, err
	}
	v := []PendingContainerEdit{}
	if len(out) == 0 {
		return v, nil
	}
	return v, json.Unmarshal(out, &v)
}

func (s *Store) DeletePendingContainerEdit(name string) error {
	return s.exec("DELETE FROM pending_container_edits WHERE name=" + q(strings.TrimSpace(name)) + ";")
}

func (s *Store) CreateAPIKey(name, prefix, hash, scopes string) (int64, error) {
	if err := s.exec(fmt.Sprintf("INSERT INTO api_keys(name,prefix,secret_hash,scopes,created_at) VALUES(%s,%s,%s,%s,%d);", q(name), q(prefix), q(hash), q(scopes), time.Now().Unix())); err != nil {
		return 0, err
	}
	k, ok, err := s.APIKeyByPrefix(prefix)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, errors.New("created api key not found")
	}
	return k.ID, nil
}
func (s *Store) ListAPIKeys() ([]APIKey, error) {
	out, err := s.run("SELECT id,name,prefix,scopes,created_at,last_used_at FROM api_keys ORDER BY id DESC;")
	if err != nil {
		return nil, err
	}
	v := []APIKey{}
	if len(out) == 0 {
		return v, nil
	}
	return v, json.Unmarshal(out, &v)
}

func (s *Store) UpsertAgent(a Agent) error {
	if a.CreatedAt == 0 {
		a.CreatedAt = time.Now().Unix()
	}
	return s.exec(fmt.Sprintf(`INSERT INTO agents(id,name,url,server_cert,version,created_at,last_seen_at)
VALUES(%s,%s,%s,%s,%s,%d,%d)
ON CONFLICT(id) DO UPDATE SET name=excluded.name,url=excluded.url,server_cert=excluded.server_cert,version=excluded.version,last_seen_at=excluded.last_seen_at;`,
		q(a.ID), q(a.Name), q(a.URL), q(a.ServerCert), q(a.Version), a.CreatedAt, a.LastSeenAt))
}

func (s *Store) ListAgents() ([]Agent, error) {
	out, err := s.run("SELECT id,name,url,server_cert,version,created_at,last_seen_at FROM agents ORDER BY name,id;")
	if err != nil {
		return nil, err
	}
	v := []Agent{}
	if len(out) == 0 {
		return v, nil
	}
	return v, json.Unmarshal(out, &v)
}

func (s *Store) AgentByID(id string) (Agent, bool, error) {
	out, err := s.run("SELECT id,name,url,server_cert,version,created_at,last_seen_at FROM agents WHERE id=" + q(id) + " LIMIT 1;")
	if err != nil {
		return Agent{}, false, err
	}
	v := []Agent{}
	if len(out) == 0 {
		return Agent{}, false, nil
	}
	if err := json.Unmarshal(out, &v); err != nil {
		return Agent{}, false, err
	}
	if len(v) == 0 {
		return Agent{}, false, nil
	}
	return v[0], true, nil
}

func (s *Store) DeleteAgent(id string) error {
	return s.exec("BEGIN IMMEDIATE;DELETE FROM container_group_members WHERE host_id=" + q(id) + ";DELETE FROM agents WHERE id=" + q(id) + ";COMMIT;")
}

func (s *Store) TouchAgent(id string) {
	_ = s.exec(fmt.Sprintf("UPDATE agents SET last_seen_at=%d WHERE id=%s;", time.Now().Unix(), q(id)))
}

func (s *Store) ListContainerGroups() ([]ContainerGroup, error) {
	out, err := s.run("SELECT id,name,created_at,updated_at FROM container_groups ORDER BY name COLLATE NOCASE,id;")
	if err != nil {
		return nil, err
	}
	groups := []ContainerGroup{}
	if len(out) > 0 {
		if err := json.Unmarshal(out, &groups); err != nil {
			return nil, err
		}
	}
	for i := range groups {
		m, err := s.ContainerGroupMembers(groups[i].ID)
		if err != nil {
			return nil, err
		}
		groups[i].Members = m
	}
	return groups, nil
}
func (s *Store) ContainerGroupByID(id int64) (ContainerGroup, bool, error) {
	out, err := s.run(fmt.Sprintf("SELECT id,name,created_at,updated_at FROM container_groups WHERE id=%d LIMIT 1;", id))
	if err != nil {
		return ContainerGroup{}, false, err
	}
	var v []ContainerGroup
	if len(out) == 0 {
		return ContainerGroup{}, false, nil
	}
	if err := json.Unmarshal(out, &v); err != nil {
		return ContainerGroup{}, false, err
	}
	if len(v) == 0 {
		return ContainerGroup{}, false, nil
	}
	m, err := s.ContainerGroupMembers(id)
	if err != nil {
		return ContainerGroup{}, false, err
	}
	v[0].Members = m
	return v[0], true, nil
}
func (s *Store) ContainerGroupMembers(id int64) ([]ContainerGroupMember, error) {
	out, err := s.run(fmt.Sprintf("SELECT group_id,host_id,container_name FROM container_group_members WHERE group_id=%d ORDER BY host_id,container_name COLLATE NOCASE;", id))
	if err != nil {
		return nil, err
	}
	v := []ContainerGroupMember{}
	if len(out) > 0 {
		if err := json.Unmarshal(out, &v); err != nil {
			return nil, err
		}
	}
	return v, nil
}
func (s *Store) CreateContainerGroup(name string, members []ContainerGroupMember) (ContainerGroup, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return ContainerGroup{}, errors.New("group name is required")
	}
	now := time.Now().Unix()
	var sql strings.Builder
	sql.WriteString("BEGIN IMMEDIATE;")
	sql.WriteString(fmt.Sprintf("INSERT INTO container_groups(name,created_at,updated_at) VALUES(%s,%d,%d);", q(name), now, now))
	sql.WriteString("CREATE TEMP TABLE IF NOT EXISTS _zc_gid(id INTEGER);DELETE FROM _zc_gid;INSERT INTO _zc_gid VALUES(last_insert_rowid());")
	for _, m := range members {
		sql.WriteString(fmt.Sprintf("INSERT OR IGNORE INTO container_group_members(group_id,host_id,container_name) SELECT id,%s,%s FROM _zc_gid;", q(m.HostID), q(m.ContainerName)))
	}
	sql.WriteString("SELECT id FROM _zc_gid;COMMIT;")
	out, err := s.run(sql.String())
	if err != nil {
		return ContainerGroup{}, err
	}
	var ids []map[string]any
	if err := json.Unmarshal(out, &ids); err != nil || len(ids) == 0 {
		return ContainerGroup{}, errors.New("created group id unavailable")
	}
	id := int64(ids[0]["id"].(float64))
	g, _, err := s.ContainerGroupByID(id)
	return g, err
}
func (s *Store) UpdateContainerGroup(id int64, name string, members []ContainerGroupMember) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("group name is required")
	}
	now := time.Now().Unix()
	var sql strings.Builder
	sql.WriteString("BEGIN IMMEDIATE;")
	sql.WriteString(fmt.Sprintf("UPDATE container_groups SET name=%s,updated_at=%d WHERE id=%d;DELETE FROM container_group_members WHERE group_id=%d;", q(name), now, id, id))
	for _, m := range members {
		sql.WriteString(fmt.Sprintf("INSERT OR IGNORE INTO container_group_members(group_id,host_id,container_name) VALUES(%d,%s,%s);", id, q(m.HostID), q(m.ContainerName)))
	}
	sql.WriteString("COMMIT;")
	return s.exec(sql.String())
}
func (s *Store) DeleteContainerGroup(id int64) error {
	return s.exec(fmt.Sprintf("DELETE FROM container_groups WHERE id=%d;", id))
}
func (s *Store) RemoveContainerGroupHost(hostID string) error {
	return s.exec("DELETE FROM container_group_members WHERE host_id=" + q(hostID) + ";")
}

func (s *Store) UpsertUpdateCheck(v UpdateCheck) error {
	if v.CheckedAt == 0 {
		v.CheckedAt = time.Now().Unix()
	}
	return s.exec(fmt.Sprintf(`INSERT INTO update_checks(resource_id,image_ref,current_digest,remote_digest,status,checked_at)
VALUES(%s,%s,%s,%s,%s,%d)
ON CONFLICT(resource_id) DO UPDATE SET image_ref=excluded.image_ref,current_digest=excluded.current_digest,remote_digest=excluded.remote_digest,status=excluded.status,checked_at=excluded.checked_at;`,
		q(v.ResourceID), q(v.ImageRef), q(v.CurrentDigest), q(v.RemoteDigest), q(v.Status), v.CheckedAt))
}

func (s *Store) ListUpdateChecks() ([]UpdateCheck, error) {
	out, err := s.run("SELECT resource_id,image_ref,current_digest,remote_digest,status,checked_at FROM update_checks ORDER BY checked_at DESC;")
	if err != nil {
		return nil, err
	}
	v := []UpdateCheck{}
	if len(out) == 0 {
		return v, nil
	}
	return v, json.Unmarshal(out, &v)
}
func (s *Store) APIKeyByPrefix(prefix string) (APIKey, bool, error) {
	out, err := s.run("SELECT id,name,prefix,secret_hash,scopes,created_at,last_used_at FROM api_keys WHERE prefix=" + q(prefix) + " LIMIT 1;")
	if err != nil {
		return APIKey{}, false, err
	}
	var v []APIKey
	if len(out) == 0 {
		return APIKey{}, false, nil
	}
	if err := json.Unmarshal(out, &v); err != nil {
		return APIKey{}, false, err
	}
	if len(v) == 0 {
		return APIKey{}, false, nil
	}
	return v[0], true, nil
}
func (s *Store) TouchAPIKey(id int64) {
	_ = s.exec(fmt.Sprintf("UPDATE api_keys SET last_used_at=%d WHERE id=%d;", time.Now().Unix(), id))
}
func (s *Store) DeleteAPIKey(id int64) error {
	return s.exec("DELETE FROM api_keys WHERE id=" + strconv.FormatInt(id, 10) + ";")
}
func (s *Store) lastID() (int64, error) {
	out, err := s.run("SELECT last_insert_rowid() AS id;")
	if err != nil {
		return 0, err
	}
	var v []map[string]any
	if err := json.Unmarshal(out, &v); err != nil {
		return 0, err
	}
	if len(v) == 0 {
		return 0, errors.New("no id")
	}
	return int64(v[0]["id"].(float64)), nil
}

func (s *Store) ListRegistries() ([]Registry, error) {
	out, err := s.run("SELECT id,name,server,username,secret_enc,created_at,updated_at FROM registries ORDER BY name,server;")
	if err != nil {
		return nil, err
	}
	v := []Registry{}
	if len(out) == 0 {
		return v, nil
	}
	return v, json.Unmarshal(out, &v)
}

func (s *Store) RegistryByID(id int64) (Registry, bool, error) {
	out, err := s.run("SELECT id,name,server,username,secret_enc,created_at,updated_at FROM registries WHERE id=" + strconv.FormatInt(id, 10) + " LIMIT 1;")
	if err != nil {
		return Registry{}, false, err
	}
	v := []Registry{}
	if len(out) == 0 {
		return Registry{}, false, nil
	}
	if err := json.Unmarshal(out, &v); err != nil {
		return Registry{}, false, err
	}
	if len(v) == 0 {
		return Registry{}, false, nil
	}
	return v[0], true, nil
}

func (s *Store) RegistryByServer(server string) (Registry, bool, error) {
	out, err := s.run("SELECT id,name,server,username,secret_enc,created_at,updated_at FROM registries WHERE server=" + q(server) + " LIMIT 1;")
	if err != nil {
		return Registry{}, false, err
	}
	v := []Registry{}
	if len(out) == 0 {
		return Registry{}, false, nil
	}
	if err := json.Unmarshal(out, &v); err != nil {
		return Registry{}, false, err
	}
	if len(v) == 0 {
		return Registry{}, false, nil
	}
	return v[0], true, nil
}

func (s *Store) UpsertRegistry(id int64, name, server, username, secretEnc string) (int64, error) {
	now := time.Now().Unix()
	if id > 0 {
		if err := s.exec(fmt.Sprintf("UPDATE registries SET name=%s,server=%s,username=%s,secret_enc=%s,updated_at=%d WHERE id=%d;", q(name), q(server), q(username), q(secretEnc), now, id)); err != nil {
			return 0, err
		}
		return id, nil
	}
	if err := s.exec(fmt.Sprintf("INSERT INTO registries(name,server,username,secret_enc,created_at,updated_at) VALUES(%s,%s,%s,%s,%d,%d);", q(name), q(server), q(username), q(secretEnc), now, now)); err != nil {
		return 0, err
	}
	r, ok, err := s.RegistryByServer(server)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, errors.New("created registry not found")
	}
	return r.ID, nil
}
func (s *Store) DeleteRegistry(id int64) error {
	return s.exec("DELETE FROM registries WHERE id=" + strconv.FormatInt(id, 10) + ";")
}

func (s *Store) AdoptContainer(name string) error {
	return s.exec(fmt.Sprintf("INSERT INTO adopted_containers(name,adopted_at) VALUES(%s,%d) ON CONFLICT(name) DO UPDATE SET adopted_at=excluded.adopted_at;", q(name), time.Now().Unix()))
}
func (s *Store) IsContainerAdopted(name string) bool {
	out, err := s.run("SELECT name FROM adopted_containers WHERE name=" + q(name) + " LIMIT 1;")
	if err != nil || len(out) == 0 {
		return false
	}
	var v []map[string]any
	if json.Unmarshal(out, &v) != nil {
		return false
	}
	return len(v) > 0
}
func (s *Store) ForgetAdoptedContainer(name string) error {
	return s.exec("DELETE FROM adopted_containers WHERE name=" + q(name) + ";")
}
