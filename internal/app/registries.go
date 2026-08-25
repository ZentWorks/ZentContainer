package app

import (
	"crypto/tls"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ZentWorks/ZentContainer/internal/dockerx"
	"github.com/ZentWorks/ZentContainer/internal/secretbox"
)

type registryInput struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Server   string `json:"server"`
	Username string `json:"username"`
	Secret   string `json:"secret"`
}

func normalizeRegistryServer(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "https://")
	v = strings.TrimPrefix(v, "http://")
	v = strings.TrimSuffix(v, "/")
	if v == "index.docker.io" || v == "registry-1.docker.io" {
		return "docker.io"
	}
	return strings.ToLower(v)
}

func registryForImage(ref string) string {
	ref = strings.TrimSpace(ref)
	first := strings.SplitN(ref, "/", 2)[0]
	if strings.Contains(first, ".") || strings.Contains(first, ":") || first == "localhost" {
		return normalizeRegistryServer(first)
	}
	return "docker.io"
}

func (a *App) registryAuthForImage(ref string) string {
	server := registryForImage(ref)
	r, ok, err := a.db.RegistryByServer(server)
	if err != nil || !ok || r.SecretEnc == "" {
		return ""
	}
	secret, err := secretbox.Decrypt(a.masterKey, r.SecretEnc)
	if err != nil {
		return ""
	}
	h, err := dockerx.RegistryAuth(r.Username, secret, r.Server)
	if err != nil {
		return ""
	}
	return h
}

func (a *App) registries(w http.ResponseWriter, r *http.Request) {
	v, err := a.db.ListRegistries()
	if err != nil {
		errorJSON(w, 500, "db_error", err.Error())
		return
	}
	out := make([]map[string]any, 0, len(v))
	for _, x := range v {
		out = append(out, map[string]any{"id": x.ID, "name": x.Name, "server": x.Server, "username": x.Username, "has_secret": x.SecretEnc != "", "created_at": x.CreatedAt, "updated_at": x.UpdatedAt})
	}
	writeJSON(w, out)
}

func (a *App) registrySave(w http.ResponseWriter, r *http.Request) {
	var in registryInput
	if !decodeJSON(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	in.Server = normalizeRegistryServer(in.Server)
	in.Username = strings.TrimSpace(in.Username)
	if in.Name == "" || in.Server == "" {
		errorJSON(w, 400, "invalid_registry", "name and server are required")
		return
	}
	id := in.ID
	if pathID := strings.TrimSpace(r.PathValue("id")); pathID != "" {
		parsed, err := strconv.ParseInt(pathID, 10, 64)
		if err != nil || parsed <= 0 {
			errorJSON(w, 400, "invalid_id", "invalid registry id")
			return
		}
		id = parsed
	}
	secretEnc := ""
	if id > 0 {
		existing, ok, err := a.db.RegistryByID(id)
		if err != nil {
			errorJSON(w, 500, "db_error", err.Error())
			return
		}
		if !ok {
			errorJSON(w, 404, "registry_not_found", "Registry not found")
			return
		}
		secretEnc = existing.SecretEnc
	}
	if in.Secret != "" {
		var err error
		secretEnc, err = secretbox.Encrypt(a.masterKey, in.Secret)
		if err != nil {
			errorJSON(w, 500, "encrypt_failed", err.Error())
			return
		}
	}
	newID, err := a.db.UpsertRegistry(id, in.Name, in.Server, in.Username, secretEnc)
	if err != nil {
		errorJSON(w, 400, "registry_save_failed", err.Error())
		return
	}
	a.db.AddAudit(a.currentActor(r), "registry.save", in.Server, "")
	writeJSON(w, map[string]any{"ok": true, "id": newID})
}
func (a *App) registryDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		errorJSON(w, 400, "invalid_id", "invalid registry id")
		return
	}
	if err := a.db.DeleteRegistry(id); err != nil {
		errorJSON(w, 500, "db_error", err.Error())
		return
	}
	a.db.AddAudit(a.currentActor(r), "registry.delete", r.PathValue("id"), "")
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) registryTest(w http.ResponseWriter, r *http.Request) {
	var in registryInput
	if !decodeJSON(w, r, &in) {
		return
	}
	server := normalizeRegistryServer(in.Server)
	if server == "" {
		errorJSON(w, 400, "invalid_registry", "server is required")
		return
	}
	if in.Secret == "" && in.ID > 0 {
		if ex, ok, _ := a.db.RegistryByID(in.ID); ok {
			in.Username = ex.Username
			if ex.SecretEnc != "" {
				in.Secret, _ = secretbox.Decrypt(a.masterKey, ex.SecretEnc)
			}
		}
	}
	scheme := "https"
	host := server
	if strings.HasPrefix(host, "localhost:") || strings.HasPrefix(host, "127.0.0.1:") {
		scheme = "http"
	}
	u := scheme + "://" + host + "/v2/"
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, u, nil)
	if err != nil {
		errorJSON(w, 400, "invalid_registry", err.Error())
		return
	}
	if in.Username != "" {
		req.SetBasicAuth(in.Username, in.Secret)
	}
	client := &http.Client{Timeout: 8 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}}
	resp, err := client.Do(req)
	if err != nil {
		errorJSON(w, 502, "registry_unreachable", err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		errorJSON(w, 502, "registry_error", "Registry returned "+resp.Status)
		return
	}
	msg := "Registry erreichbar"
	if resp.StatusCode == http.StatusUnauthorized {
		msg = "Registry erreichbar; Authentifizierung wird von der Registry angefordert"
	}
	writeJSON(w, map[string]any{"ok": true, "status": resp.StatusCode, "message": msg})
}
