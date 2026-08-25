package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ZentWorks/ZentContainer/internal/agentsec"
	"github.com/ZentWorks/ZentContainer/internal/auth"
	"github.com/ZentWorks/ZentContainer/internal/store"
	"github.com/ZentWorks/ZentContainer/internal/version"
)

type pairRequest struct {
	URL  string `json:"url"`
	Code string `json:"code"`
	Name string `json:"name"`
}

type agentPairRequest struct {
	PairingCode      string `json:"pairing_code"`
	ControllerCA     string `json:"controller_ca"`
	ControllerURL    string `json:"controller_url,omitempty"`
	ControllerName   string `json:"controller_name"`
	ControllerPort   int    `json:"controller_port,omitempty"`
	ControllerScheme string `json:"controller_scheme,omitempty"`
}

type agentPairResponse struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Version    string `json:"version"`
	ServerCert string `json:"server_cert"`
}

func (a *App) ensureRoleSecurity() error {
	switch a.db.Role() {
	case "controller":
		return agentsec.EnsureControllerPKI(a.cfg.CertificatesDir())
	case "agent":
		if err := agentsec.EnsureAgentServerCert(a.cfg.CertificatesDir()); err != nil {
			return err
		}
		code, _, _ := a.db.GetSetting("pairing_code")
		master, _, _ := a.db.GetSetting("master_url")
		if master == "" && !strings.HasPrefix(code, "ZCA2-") {
			return a.resetAgentPairingCode()
		}
	}
	return nil
}

func (a *App) resetAgentPairingCode() error {
	if err := agentsec.EnsureAgentServerCert(a.cfg.CertificatesDir()); err != nil {
		return err
	}
	fp, err := agentsec.CertFingerprintFile(a.cfg.AgentCertPath())
	if err != nil {
		return err
	}
	secret, err := auth.RandomToken(24)
	if err != nil {
		return err
	}
	code := "ZCA2-" + fp[:32] + "-" + secret
	return a.db.SetSettings(map[string]string{
		"controller_ca": "",
		"master_url":    "",
		"pairing_code":  code,
	})
}

func agentListenPort(addr string) int {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		if strings.HasPrefix(addr, ":") {
			port = strings.TrimPrefix(addr, ":")
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return 9444
	}
	return n
}

// agentPublishedPort returns the host-side port Docker publishes for the agent
// management port when ZentContainer can reliably inspect its own container.
// A zero value means the mapping could not be determined and the UI should
// present the configured management port as a hint instead of inventing one.
func (a *App) agentPublishedPort() int {
	containerID, err := os.Hostname()
	if err != nil || strings.TrimSpace(containerID) == "" {
		return 0
	}
	d, err := a.docker()
	if err != nil {
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	raw, err := d.ContainerInspect(ctx, containerID)
	if err != nil {
		return 0
	}
	var inspect struct {
		NetworkSettings struct {
			Ports map[string][]struct {
				HostIP   string `json:"HostIp"`
				HostPort string `json:"HostPort"`
			} `json:"Ports"`
		} `json:"NetworkSettings"`
	}
	if json.Unmarshal(raw, &inspect) != nil {
		return 0
	}
	key := strconv.Itoa(agentListenPort(a.cfg.AgentListen)) + "/tcp"
	for _, b := range inspect.NetworkSettings.Ports[key] {
		if n, err := strconv.Atoi(b.HostPort); err == nil && n > 0 && n <= 65535 {
			return n
		}
	}
	return 0
}

func (a *App) startAgentServer() {
	if a.db.Role() != "agent" {
		return
	}
	a.agentOnce.Do(func() {
		go func() {
			setState := func(active bool, errText string) {
				a.agentStateMu.Lock()
				a.agentListening = active
				a.agentListenError = errText
				a.agentStateMu.Unlock()
			}
			if err := a.ensureRoleSecurity(); err != nil {
				setState(false, err.Error())
				log.Printf("agent security setup failed: %v", err)
				return
			}
			mux := http.NewServeMux()
			mux.HandleFunc("POST /agent/pair", a.agentPair)
			mux.HandleFunc("POST /agent/unpair", a.agentRequireMTLS(a.agentUnpair))
			a.agentResourceRoutes(mux)
			srv := &http.Server{
				Addr:              a.cfg.AgentListen,
				Handler:           a.securityHeaders(mux),
				ReadHeaderTimeout: 10 * time.Second,
				IdleTimeout:       90 * time.Second,
				TLSConfig: &tls.Config{
					MinVersion: tls.VersionTLS13,
					ClientAuth: tls.RequestClientCert,
				},
			}
			ln, err := net.Listen("tcp", a.cfg.AgentListen)
			if err != nil {
				setState(false, err.Error())
				log.Printf("agent management listen failed on %s: %v", a.cfg.AgentListen, err)
				return
			}
			setState(true, "")
			log.Printf("ZentContainer agent management listening securely on %s", a.cfg.AgentListen)
			if err := srv.ServeTLS(ln, a.cfg.AgentCertPath(), a.cfg.AgentKeyPath()); err != nil && !errors.Is(err, http.ErrServerClosed) {
				setState(false, err.Error())
				log.Printf("agent management server stopped: %v", err)
			}
		}()
	})
}

func (a *App) agentResourceRoutes(m *http.ServeMux) {
	wrap := a.agentRequireMTLS
	m.HandleFunc("GET /agent/api/v1/system", wrap(a.system))
	m.HandleFunc("GET /agent/api/v1/settings", wrap(a.settingsGet))
	m.HandleFunc("PUT /agent/api/v1/settings", wrap(a.settingsPut))
	m.HandleFunc("GET /agent/api/v1/dashboard", wrap(a.dashboard))
	m.HandleFunc("GET /agent/api/v1/host-metrics", wrap(a.hostMetrics))
	m.HandleFunc("GET /agent/api/v1/hardware/devices", wrap(a.hardwareDevices))
	m.HandleFunc("GET /agent/api/v1/resources/map", wrap(a.resourceMap))
	m.HandleFunc("GET /agent/api/v1/storage", wrap(a.storageAnalysis))
	m.HandleFunc("POST /agent/api/v1/storage/cleanup", wrap(a.storageCleanup))
	m.HandleFunc("GET /agent/api/v1/events", wrap(a.dockerEvents))
	m.HandleFunc("GET /agent/api/v1/backups", wrap(a.backupList))
	m.HandleFunc("POST /agent/api/v1/backups", wrap(a.backupCreate))
	m.HandleFunc("POST /agent/api/v1/backups/import", wrap(a.backupImport))
	m.HandleFunc("DELETE /agent/api/v1/backups/{id}", wrap(a.backupDelete))
	m.HandleFunc("POST /agent/api/v1/backups/{id}/restore", wrap(a.backupRestore))
	m.HandleFunc("GET /agent/api/v1/backups/{id}/download", wrap(a.backupDownload))
	m.HandleFunc("GET /agent/api/v1/containers", wrap(a.containers))
	m.HandleFunc("GET /agent/api/v1/containers/stats", wrap(a.containerStatsBatch))
	m.HandleFunc("POST /agent/api/v1/containers", wrap(a.containerCreate))
	m.HandleFunc("POST /agent/api/v1/containers/preflight", wrap(a.containerPreflight))
	m.HandleFunc("PUT /agent/api/v1/containers/{id}", wrap(a.containerEdit))
	m.HandleFunc("GET /agent/api/v1/containers/{id}", wrap(a.containerInspect))
	m.HandleFunc("DELETE /agent/api/v1/containers/{id}", wrap(a.containerDelete))
	m.HandleFunc("POST /agent/api/v1/containers/{id}/adopt", wrap(a.containerAdopt))
	m.HandleFunc("POST /agent/api/v1/containers/{id}/{action}", wrap(a.containerAction))
	m.HandleFunc("GET /agent/api/v1/containers/{id}/logs", wrap(a.containerLogs))
	m.HandleFunc("GET /agent/api/v1/containers/{id}/stats", wrap(a.containerStats))
	m.HandleFunc("GET /agent/api/v1/containers/{id}/processes", wrap(a.containerProcesses))
	m.HandleFunc("GET /agent/api/v1/containers/{id}/diagnostics", wrap(a.containerDiagnostics))
	m.HandleFunc("GET /agent/api/v1/containers/{id}/delete-plan", wrap(a.containerDeletePlan))
	m.HandleFunc("GET /agent/api/v1/containers/{id}/files", wrap(a.containerFiles))
	m.HandleFunc("GET /agent/api/v1/containers/{id}/files/content", wrap(a.containerFileGet))
	m.HandleFunc("PUT /agent/api/v1/containers/{id}/files/content", wrap(a.containerFilePut))
	m.HandleFunc("GET /agent/api/v1/containers/{id}/files/download", wrap(a.containerFileDownload))
	m.HandleFunc("POST /agent/api/v1/containers/{id}/convert-compose", wrap(a.containerConvertCompose))
	m.HandleFunc("PUT /agent/api/v1/containers/{id}/compose-image", wrap(a.containerExternalComposeImage))
	m.HandleFunc("GET /agent/api/v1/containers/{id}/terminal", wrap(a.containerTerminal))
	m.HandleFunc("GET /agent/api/v1/images", wrap(a.images))
	m.HandleFunc("POST /agent/api/v1/images/pull", wrap(a.imagePull))
	m.HandleFunc("GET /agent/api/v1/images/{id}", wrap(a.imageInspect))
	m.HandleFunc("GET /agent/api/v1/images/{id}/history", wrap(a.imageHistory))
	m.HandleFunc("DELETE /agent/api/v1/images/{id}", wrap(a.imageDelete))
	m.HandleFunc("GET /agent/api/v1/volumes", wrap(a.volumes))
	m.HandleFunc("POST /agent/api/v1/volumes", wrap(a.volumeCreate))
	m.HandleFunc("GET /agent/api/v1/volumes/{name}", wrap(a.volumeInspect))
	m.HandleFunc("GET /agent/api/v1/volumes/{name}/size", wrap(a.volumeSize))
	m.HandleFunc("DELETE /agent/api/v1/volumes/{name}", wrap(a.volumeDelete))
	m.HandleFunc("GET /agent/api/v1/volumes/{name}/files", wrap(a.volumeFiles))
	m.HandleFunc("GET /agent/api/v1/volumes/{name}/file", wrap(a.volumeDownload))
	m.HandleFunc("PUT /agent/api/v1/volumes/{name}/file", wrap(a.volumeWrite))
	m.HandleFunc("POST /agent/api/v1/volumes/{name}/upload", wrap(a.volumeUpload))
	m.HandleFunc("GET /agent/api/v1/volumes/{name}/archive", wrap(a.volumeArchive))
	m.HandleFunc("POST /agent/api/v1/volumes/{name}/mkdir", wrap(a.volumeMkdir))
	m.HandleFunc("DELETE /agent/api/v1/volumes/{name}/file", wrap(a.volumeFileDelete))
	m.HandleFunc("GET /agent/api/v1/networks", wrap(a.networks))
	m.HandleFunc("POST /agent/api/v1/networks", wrap(a.networkCreate))
	m.HandleFunc("GET /agent/api/v1/networks/{id}", wrap(a.networkInspect))
	m.HandleFunc("DELETE /agent/api/v1/networks/{id}", wrap(a.networkDelete))
	m.HandleFunc("POST /agent/api/v1/networks/{id}/connect", wrap(a.networkConnect))
	m.HandleFunc("POST /agent/api/v1/networks/{id}/disconnect", wrap(a.networkDisconnect))
	m.HandleFunc("GET /agent/api/v1/projects", wrap(a.projectList))
	m.HandleFunc("POST /agent/api/v1/projects/import", wrap(a.projectImport))
	m.HandleFunc("POST /agent/api/v1/projects", wrap(a.projectSave))
	m.HandleFunc("POST /agent/api/v1/projects/validate", wrap(a.projectValidateContent))
	m.HandleFunc("GET /agent/api/v1/projects/{name}", wrap(a.projectGet))
	m.HandleFunc("GET /agent/api/v1/projects/{name}/files", wrap(a.projectFiles))
	m.HandleFunc("GET /agent/api/v1/projects/{name}/file", wrap(a.projectFileGet))
	m.HandleFunc("PUT /agent/api/v1/projects/{name}/file", wrap(a.projectFilePut))
	m.HandleFunc("DELETE /agent/api/v1/projects/{name}/file", wrap(a.projectFileDelete))
	m.HandleFunc("POST /agent/api/v1/projects/{name}/mkdir", wrap(a.projectMkdir))
	m.HandleFunc("POST /agent/api/v1/projects/{name}/rename", wrap(a.projectRename))
	m.HandleFunc("POST /agent/api/v1/projects/{name}/upload", wrap(a.projectUpload))
	m.HandleFunc("GET /agent/api/v1/projects/{name}/download", wrap(a.projectDownload))
	m.HandleFunc("GET /agent/api/v1/projects/{name}/analysis", wrap(a.projectAnalysis))
	m.HandleFunc("GET /agent/api/v1/projects/{name}/status", wrap(a.projectStatus))
	m.HandleFunc("GET /agent/api/v1/projects/{name}/diagnostics", wrap(a.projectDiagnostics))
	m.HandleFunc("POST /agent/api/v1/projects/{name}/build", wrap(a.projectBuild))
	m.HandleFunc("GET /agent/api/v1/projects/{name}/archive", wrap(a.projectArchive))
	m.HandleFunc("PUT /agent/api/v1/projects/{name}/compose-file", wrap(a.projectComposeFile))
	m.HandleFunc("GET /agent/api/v1/projects/{name}/file-revisions", wrap(a.projectFileRevisions))
	m.HandleFunc("GET /agent/api/v1/projects/{name}/file-revisions/{revision}", wrap(a.projectFileRevisionGet))
	m.HandleFunc("POST /agent/api/v1/projects/{name}/file-revisions/{revision}/restore", wrap(a.projectFileRevisionRestore))
	m.HandleFunc("GET /agent/api/v1/projects/{name}/revisions", wrap(a.projectRevisions))
	m.HandleFunc("GET /agent/api/v1/projects/{name}/revisions/{revision}", wrap(a.projectRevisionGet))
	m.HandleFunc("POST /agent/api/v1/projects/{name}/revisions/{revision}/restore", wrap(a.projectRevisionRestore))
	m.HandleFunc("PUT /agent/api/v1/projects/{name}", wrap(a.projectSaveNamed))
	m.HandleFunc("DELETE /agent/api/v1/projects/{name}", wrap(a.projectDelete))
	m.HandleFunc("POST /agent/api/v1/projects/{name}/{action}", wrap(a.projectAction))
	m.HandleFunc("GET /agent/api/v1/projects/{name}/logs", wrap(a.projectLogs))
	m.HandleFunc("GET /agent/api/v1/registries", wrap(a.registries))
	m.HandleFunc("POST /agent/api/v1/registries", wrap(a.registrySave))
	m.HandleFunc("PUT /agent/api/v1/registries/{id}", wrap(a.registrySave))
	m.HandleFunc("DELETE /agent/api/v1/registries/{id}", wrap(a.registryDelete))
	m.HandleFunc("POST /agent/api/v1/registries/test", wrap(a.registryTest))
}

func (a *App) agentRequireMTLS(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ca, ok, _ := a.db.GetSetting("controller_ca")
		if !ok || ca == "" {
			errorJSON(w, 403, "agent_not_paired", "Agent is not paired with a controller")
			return
		}
		if r.TLS == nil || agentsec.VerifyClientCertificate(peerRaw(r.TLS), []byte(ca)) != nil {
			errorJSON(w, 403, "invalid_controller_certificate", "A trusted controller certificate is required")
			return
		}
		fn(w, r)
	}
}

// PeerCertificatesRaw is implemented below through a tiny helper because tls.ConnectionState
// exposes parsed certificates, while x509 verification needs the original DER chain.
func peerRaw(state *tls.ConnectionState) [][]byte {
	if state == nil {
		return nil
	}
	out := make([][]byte, 0, len(state.PeerCertificates))
	for _, c := range state.PeerCertificates {
		out = append(out, c.Raw)
	}
	return out
}

func normalizeControllerURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return "", errors.New("invalid controller URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("controller URL must use http or https")
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("controller URL must not contain credentials, path, query or fragment")
	}
	u.Path = ""
	return strings.TrimRight(u.String(), "/"), nil
}

func (a *App) agentPair(w http.ResponseWriter, r *http.Request) {
	a.pairingMu.Lock()
	defer a.pairingMu.Unlock()
	if a.db.Role() != "agent" {
		errorJSON(w, 404, "not_agent", "This instance is not an agent")
		return
	}
	var in agentPairRequest
	if !decodeJSONLimit(w, r, &in, 64<<10) {
		return
	}
	master, _, _ := a.db.GetSetting("master_url")
	if master != "" {
		errorJSON(w, 409, "already_paired", "Agent is already paired")
		return
	}
	code, _, _ := a.db.GetSetting("pairing_code")
	if code == "" || !constantString(code, in.PairingCode) {
		time.Sleep(250 * time.Millisecond)
		errorJSON(w, 401, "invalid_pairing_code", "Invalid pairing code")
		return
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(in.ControllerCA)) {
		errorJSON(w, 400, "invalid_controller_ca", "Controller CA is invalid")
		return
	}
	_ = pool
	masterURL, err := normalizeControllerURL(in.ControllerURL)
	if err != nil {
		errorJSON(w, 400, "invalid_controller_url", err.Error())
		return
	}
	if len(strings.TrimSpace(in.ControllerName)) > 120 {
		errorJSON(w, 400, "invalid_controller_name", "Controller name is too long")
		return
	}
	if masterURL == "" {
		host, _, splitErr := net.SplitHostPort(r.RemoteAddr)
		if splitErr != nil {
			host = strings.TrimSpace(r.RemoteAddr)
		}
		scheme := strings.ToLower(strings.TrimSpace(in.ControllerScheme))
		if scheme != "https" {
			scheme = "http"
		}
		port := in.ControllerPort
		if port < 1 || port > 65535 {
			port = 9443
		}
		if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil && !ip.IsLoopback() && !ip.IsUnspecified() {
			masterURL = scheme + "://" + net.JoinHostPort(ip.String(), strconv.Itoa(port))
		}
	}
	name, _, _ := a.db.GetSetting("instance_name")
	id, _, _ := a.db.GetSetting("agent_id")
	cert, err := os.ReadFile(a.cfg.AgentCertPath())
	if err != nil {
		errorJSON(w, 500, "agent_certificate_error", err.Error())
		return
	}
	if err := a.db.SetSettings(map[string]string{
		"controller_ca": in.ControllerCA,
		"master_url":    masterURL,
		"pairing_code":  "",
	}); err != nil {
		errorJSON(w, 500, "pairing_state_error", err.Error())
		return
	}
	a.db.AddAudit("controller:"+in.ControllerName, "agent.paired", id, masterURL)
	writeJSON(w, agentPairResponse{ID: id, Name: name, Version: version.Version, ServerCert: string(cert)})
}

func (a *App) agentUnpair(w http.ResponseWriter, r *http.Request) {
	a.pairingMu.Lock()
	defer a.pairingMu.Unlock()
	if err := a.resetAgentPairingCode(); err != nil {
		errorJSON(w, 500, "unpair_failed", err.Error())
		return
	}
	if code, err := a.ensureLocalAccessCode(); err == nil {
		log.Printf("Agent local access code (required to reveal a pairing code): %s", code)
	}
	a.db.AddAudit("controller", "agent.unpaired", "system", "")
	writeJSON(w, map[string]any{"ok": true})
}

func normalizeAgentURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("agent address is required")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", errors.New("invalid agent address")
	}
	// Agent management is always encrypted. Even if a user pastes http://,
	// normalize it to HTTPS instead of ever allowing a plaintext pairing path.
	u.Scheme = "https"
	if u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("agent address must not contain a path, query or fragment")
	}
	host := u.Hostname()
	if host == "" {
		return "", errors.New("invalid agent host")
	}
	port := u.Port()
	if port == "" {
		port = "9444"
	}
	u.Host = net.JoinHostPort(host, port)
	u.Path, u.RawPath, u.RawQuery, u.Fragment = "", "", "", ""
	return strings.TrimRight(u.String(), "/"), nil
}

func controllerURLFromRequest(r *http.Request, publicURL string) string {
	if v := strings.TrimSpace(publicURL); v != "" {
		return strings.TrimRight(v, "/")
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if p := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))); p == "http" || p == "https" {
		scheme = p
	}
	host := strings.TrimSpace(r.Host)
	if host == "" || strings.ContainsAny(host, " /\\") {
		return ""
	}
	u := &url.URL{Scheme: scheme, Host: host}
	return strings.TrimRight(u.String(), "/")
}
func (a *App) pairAgent(w http.ResponseWriter, r *http.Request) {
	var in pairRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.Code) == "" {
		errorJSON(w, 400, "invalid_pairing", "Agent address and pairing code are required")
		return
	}
	normalizedURL, err := normalizeAgentURL(in.URL)
	if err != nil {
		errorJSON(w, 400, "invalid_agent_url", "Agent address is invalid. Enter an IP, hostname or host:port.")
		return
	}
	in.URL = normalizedURL
	parts := strings.SplitN(in.Code, "-", 3)
	if len(parts) != 3 || parts[0] != "ZCA2" || len(parts[1]) != 32 {
		errorJSON(w, 400, "invalid_pairing_code", "Pairing code format is invalid")
		return
	}
	expectedPrefix := strings.ToLower(parts[1])
	tr := &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // certificate is pinned by its SHA-256 fingerprint below
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("agent presented no certificate")
			}
			h := sha256.Sum256(rawCerts[0])
			fp := hex.EncodeToString(h[:])
			if !strings.HasPrefix(fp, expectedPrefix) {
				return errors.New("agent certificate fingerprint does not match pairing code")
			}
			return nil
		},
	}}
	client := &http.Client{Transport: tr, Timeout: 30 * time.Second}
	ca, err := os.ReadFile(a.cfg.ControllerCAPath())
	if err != nil {
		errorJSON(w, 500, "controller_pki_error", err.Error())
		return
	}
	instance, _, _ := a.db.GetSetting("instance_name")
	masterURL := controllerURLFromRequest(r, a.cfg.PublicURL)
	scheme := "http"
	if u, parseErr := url.Parse(masterURL); parseErr == nil && u.Scheme != "" {
		scheme = u.Scheme
	}
	controllerPort := 0
	if _, p, err := net.SplitHostPort(r.Host); err == nil {
		controllerPort, _ = strconv.Atoi(p)
	}
	if controllerPort == 0 {
		if scheme == "https" {
			controllerPort = 443
		} else {
			controllerPort = 80
		}
		if _, p, err := net.SplitHostPort(a.cfg.ListenAddr); err == nil {
			if n, e := strconv.Atoi(p); e == nil && n > 0 {
				controllerPort = n
			}
		} else if strings.HasPrefix(a.cfg.ListenAddr, ":") {
			if n, e := strconv.Atoi(strings.TrimPrefix(a.cfg.ListenAddr, ":")); e == nil && n > 0 {
				controllerPort = n
			}
		}
	}
	payload, _ := json.Marshal(agentPairRequest{PairingCode: in.Code, ControllerCA: string(ca), ControllerURL: masterURL, ControllerName: instance, ControllerPort: controllerPort, ControllerScheme: scheme})
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, in.URL+"/agent/pair", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		msg := err.Error()
		if strings.Contains(strings.ToLower(msg), "connection refused") {
			msg = "Agent-Adresse ist erreichbar, aber der sichere Agent-Dienst nimmt auf diesem Port keine Verbindung an. Prüfe auf dem Ziel: Rolle = Agent, Agent-Dienst aktiv, laufende ZentContainer-Version und Docker-Portfreigabe für 9444 (bzw. den angegebenen Host-Port)."
		}
		errorJSON(w, 502, "agent_unreachable", msg)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		errorJSON(w, resp.StatusCode, "pairing_failed", strings.TrimSpace(string(body)))
		return
	}
	var out agentPairResponse
	if err := json.Unmarshal(body, &out); err != nil || out.ID == "" || out.ServerCert == "" {
		errorJSON(w, 502, "invalid_agent_response", "Agent returned an invalid pairing response")
		return
	}
	fp, err := agentsec.CertFingerprintPEM([]byte(out.ServerCert))
	if err != nil || !strings.HasPrefix(fp, expectedPrefix) {
		errorJSON(w, 502, "agent_certificate_changed", "Agent certificate changed during pairing")
		return
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = out.Name
	}
	ag := store.Agent{ID: out.ID, Name: name, URL: in.URL, ServerCert: out.ServerCert, Version: out.Version, CreatedAt: time.Now().Unix(), LastSeenAt: time.Now().Unix()}
	verifyCtx, verifyCancel := context.WithTimeout(r.Context(), 8*time.Second)
	_, verifyErr := a.probeAgent(verifyCtx, ag)
	verifyCancel()
	if verifyErr != nil {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		if resp, cleanupErr := a.agentRequest(cleanupCtx, ag, http.MethodPost, "/agent/unpair", nil); cleanupErr == nil && resp != nil {
			_ = resp.Body.Close()
		}
		cleanupCancel()
		errorJSON(w, 502, "pairing_verification_failed", "Pairing was not saved because the authenticated mTLS verification failed: "+verifyErr.Error())
		return
	}
	if err := a.db.UpsertAgent(ag); err != nil {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		if resp, cleanupErr := a.agentRequest(cleanupCtx, ag, http.MethodPost, "/agent/unpair", nil); cleanupErr == nil && resp != nil {
			_ = resp.Body.Close()
		}
		cleanupCancel()
		errorJSON(w, 500, "db_error", "Pairing was rolled back because the Controller could not persist the Agent: "+err.Error())
		return
	}
	a.db.AddAudit(a.currentActor(r), "agent.pair", out.ID, in.URL)
	writeJSONStatus(w, 201, map[string]any{"ok": true, "host": ag})
}

func (a *App) removeAgent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ag, ok, err := a.db.AgentByID(id)
	if err != nil || !ok {
		errorJSON(w, 404, "host_not_found", "Agent not found")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	resp, unpairErr := a.agentRequest(ctx, ag, http.MethodPost, "/agent/unpair", nil)
	cancel()
	remoteUnpaired := unpairErr == nil && resp != nil && resp.StatusCode >= 200 && resp.StatusCode < 300
	if resp != nil {
		_ = resp.Body.Close()
	}
	warning := ""
	if !remoteUnpaired {
		warning = "Agent could not be reached for remote unpairing. The Controller entry was removed, but the Agent must be reset locally with its ZCL1 access code before it can be paired again."
		if unpairErr == nil && resp != nil {
			warning = fmt.Sprintf("Agent rejected remote unpairing with HTTP %d. The Controller entry was removed, but the Agent must be reset locally with its ZCL1 access code before it can be paired again.", resp.StatusCode)
		}
	}
	if err := a.db.DeleteAgent(id); err != nil {
		errorJSON(w, 500, "db_error", err.Error())
		return
	}
	detail := ag.URL
	if warning != "" {
		detail += " | " + warning
	}
	a.db.AddAudit(a.currentActor(r), "agent.remove", id, detail)
	writeJSON(w, map[string]any{"ok": true, "remote_unpaired": remoteUnpaired, "warning": warning})
}

func (a *App) agentRequest(ctx context.Context, ag store.Agent, method, path string, body io.Reader) (*http.Response, error) {
	tr, err := a.agentTransport(ag)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Transport: tr}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(ag.URL, "/")+path, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return client.Do(req)
}

func (a *App) agentTransport(ag store.Agent) (*http.Transport, error) {
	cert, err := tls.LoadX509KeyPair(a.cfg.ControllerClientCertPath(), a.cfg.ControllerClientKeyPath())
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode([]byte(ag.ServerCert))
	if block == nil {
		return nil, errors.New("stored agent certificate is invalid")
	}
	expected := sha256.Sum256(block.Bytes)
	return &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS13,
			Certificates:       []tls.Certificate{cert},
			InsecureSkipVerify: true, // exact certificate is pinned below; hostname is intentionally not required
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				if len(rawCerts) == 0 {
					return errors.New("agent presented no certificate")
				}
				got := sha256.Sum256(rawCerts[0])
				if got != expected {
					return errors.New("agent certificate pin mismatch")
				}
				return nil
			},
		}}, nil
}

func remoteResponseHeaderTimeout(method, path string) time.Duration {
	clean := strings.Trim(strings.TrimSpace(path), "/")
	segments := strings.Split(clean, "/")
	if method == http.MethodDelete && len(segments) >= 2 && segments[0] == "images" {
		return 15 * time.Minute
	}
	if method == http.MethodPost && len(segments) >= 2 {
		if segments[0] == "images" && segments[1] == "pull" {
			return 15 * time.Minute
		}
		if segments[0] == "projects" && len(segments) >= 3 {
			switch segments[2] {
			case "pull", "build", "up", "down", "restart", "restore":
				return 15 * time.Minute
			}
		}
		if segments[0] == "backups" {
			return 15 * time.Minute
		}
	}
	return 30 * time.Second
}

func (a *App) proxyAgent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("host")
	ag, ok, err := a.db.AgentByID(id)
	if err != nil || !ok {
		errorJSON(w, 404, "host_not_found", "Agent not found")
		return
	}
	tr, err := a.agentTransport(ag)
	if err != nil {
		errorJSON(w, 500, "agent_transport_error", err.Error())
		return
	}
	tr.ResponseHeaderTimeout = remoteResponseHeaderTimeout(r.Method, r.PathValue("path"))
	target, _ := url.Parse(ag.URL)
	actor := a.currentActor(r)
	path := r.PathValue("path")
	proxy := &httputil.ReverseProxy{
		Transport: tr,
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.URL.Path = "/agent/api/v1/" + path
			req.Host = target.Host
			req.Header.Del("Authorization")
			req.Header.Del("Cookie")
			req.Header.Set("X-ZC-Actor", actor)
			req.Header.Set("X-ZC-Proxy", "controller")
		},
		ModifyResponse: func(resp *http.Response) error {
			a.db.TouchAgent(id)
			return nil
		},
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, e error) {
			errorJSON(rw, 502, "agent_unreachable", e.Error())
		},
		FlushInterval: 100 * time.Millisecond,
	}
	proxy.ServeHTTP(w, r)
}

func (a *App) probeAgent(ctx context.Context, ag store.Agent) (map[string]any, error) {
	resp, err := a.agentRequest(ctx, ag, http.MethodGet, "/agent/api/v1/system", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("agent returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var v map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return nil, err
	}
	a.db.TouchAgent(ag.ID)
	return v, nil
}

func remoteRequiredScopes(r *http.Request) []string {
	return resourceRequiredScopes(r.Method, "/"+strings.TrimPrefix(r.PathValue("path"), "/"), r.URL.Query())
}
