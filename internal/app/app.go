package app

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ZentWorks/ZentContainer/internal/agentsec"
	"github.com/ZentWorks/ZentContainer/internal/auth"
	"github.com/ZentWorks/ZentContainer/internal/config"
	"github.com/ZentWorks/ZentContainer/internal/dockerx"
	"github.com/ZentWorks/ZentContainer/internal/projects"
	"github.com/ZentWorks/ZentContainer/internal/secretbox"
	"github.com/ZentWorks/ZentContainer/internal/store"
	"github.com/ZentWorks/ZentContainer/internal/version"
	"github.com/ZentWorks/ZentContainer/internal/volumehelper"
	webassets "github.com/ZentWorks/ZentContainer/web"
)

type App struct {
	cfg                      config.Config
	db                       *store.Store
	projects                 *projects.Manager
	dockerMu                 sync.Mutex
	dockerClient             *dockerx.Client
	dockerErr                string
	agentOnce                sync.Once
	masterKey                []byte
	metricsMu                sync.Mutex
	metricsData              []byte
	metricsAt                time.Time
	metricsRefreshing        bool
	storageMu                sync.Mutex
	storageData              dockerStorageSummary
	storageAt                time.Time
	storageRefreshing        bool
	containerStatsMu         sync.Mutex
	containerStatsData       containerStatsBatchResponse
	containerStatsAt         time.Time
	containerStatsPrev       map[string]containerStatsCPUPoint
	containerStatsRefreshing bool
	agentStateMu             sync.RWMutex
	agentListening           bool
	agentListenError         string
	sessionMu                sync.Mutex
	sessionCache             map[string]cachedSession
	loginRateMu              sync.Mutex
	loginAttempts            map[string]loginRateEntry
	setupMu                  sync.Mutex
	pairingMu                sync.Mutex
}

type cachedSession struct {
	Actor actor
	At    time.Time
}

type actor struct {
	Name           string
	IsAPI          bool
	User           *store.User
	Scopes         map[string]bool
	SessionHash    string
	SessionToken   string
	SessionExpires int64
}

func Run(cfg config.Config) error {
	if err := os.MkdirAll(cfg.DataDir, 0700); err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.ProjectsDir(), 0700); err != nil {
		return err
	}
	db, err := store.Open(cfg.DBPath())
	if err != nil {
		return err
	}
	key, err := secretbox.LoadOrCreate(filepath.Join(cfg.SecretsDir(), "master.key"))
	if err != nil {
		return fmt.Errorf("master key: %w", err)
	}
	a := &App{cfg: cfg, db: db, projects: projects.New(cfg.ProjectsDir()), masterKey: key, sessionCache: map[string]cachedSession{}, loginAttempts: map[string]loginRateEntry{}}
	if err := a.announceLocalAccessCode(); err != nil {
		return fmt.Errorf("local access security: %w", err)
	}
	if err := a.ensureRoleSecurity(); err != nil {
		return err
	}
	if d, err := dockerx.New(cfg.DockerSocket); err == nil {
		a.dockerClient = d
		a.storageRefreshing = true
		go a.refreshDockerStorage(d)
	} else {
		a.dockerErr = err.Error()
		log.Printf("docker unavailable at startup: %v", err)
	}
	mux := http.NewServeMux()
	a.routes(mux)
	a.startScheduler()
	a.startAgentServer()
	go a.refreshHostMetricsBackground()
	srv := &http.Server{Addr: cfg.ListenAddr, Handler: a.securityHeaders(mux), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
	log.Printf("ZentContainer %s listening on %s", version.Version, cfg.ListenAddr)
	return srv.ListenAndServe()
}

func Doctor(cfg config.Config) error {
	fmt.Println("ZentContainer Doctor")
	failed := false
	check := func(name string, err error) {
		if err != nil {
			fmt.Printf("✗ %-18s %v\n", name, err)
			failed = true
		} else {
			fmt.Printf("✓ %s\n", name)
		}
	}
	_, err := exec.LookPath("sqlite3")
	check("sqlite3", err)
	_, err = exec.LookPath("docker")
	check("docker CLI", err)
	if err == nil {
		cmd := exec.Command("docker", "compose", "version")
		_, e := cmd.CombinedOutput()
		check("docker compose", e)
	}
	_, err = os.Stat(cfg.DockerSocket)
	check("docker socket", err)
	_, err = dockerx.New(cfg.DockerSocket)
	check("Docker Engine API", err)
	err = os.MkdirAll(cfg.DataDir, 0700)
	check("data directory", err)
	if failed {
		return errors.New("one or more checks failed")
	}
	return nil
}

func (a *App) routes(m *http.ServeMux) {
	m.HandleFunc("GET /api/setup", authNoStore(a.getSetup))
	m.HandleFunc("POST /api/setup", authNoStore(a.postSetup))
	m.HandleFunc("GET /api/agent/status", authNoStore(a.agentStatus))
	m.HandleFunc("POST /api/agent/pairing-code", authNoStore(a.agentPairingCode))
	m.HandleFunc("POST /api/agent/reset-pairing", authNoStore(a.agentResetPairing))
	m.HandleFunc("POST /api/login", authNoStore(a.login))
	m.HandleFunc("POST /api/language", authNoStore(a.languagePreference))
	m.HandleFunc("POST /api/logout", authNoStore(a.require(a.logout)))
	m.HandleFunc("GET /api/me", authNoStore(a.require(a.me)))
	m.HandleFunc("GET /api/v1/system", a.requireController(a.system))
	m.HandleFunc("GET /api/v1/settings", a.requireController(a.settingsGet))
	m.HandleFunc("PUT /api/v1/settings", a.requireController(a.settingsPut))
	m.HandleFunc("PUT /api/v1/account/password", authNoStore(a.requireController(a.changePassword)))
	m.HandleFunc("PUT /api/v1/account/language", authNoStore(a.requireController(a.accountLanguage)))
	m.HandleFunc("GET /api/v1/dashboard", a.requireController(a.dashboard))
	m.HandleFunc("GET /api/v1/host-metrics", a.requireController(a.hostMetrics))
	m.HandleFunc("GET /api/v1/hosts", a.requireController(a.hosts))
	m.HandleFunc("GET /api/v1/hardware/devices", a.requireController(a.hardwareDevices))
	m.HandleFunc("GET /api/v1/resources/map", a.requireController(a.resourceMap))
	m.HandleFunc("GET /api/v1/storage", a.requireController(a.storageAnalysis))
	m.HandleFunc("POST /api/v1/storage/cleanup", a.requireController(a.storageCleanup))
	m.HandleFunc("GET /api/v1/events", a.requireController(a.dockerEvents))
	m.HandleFunc("GET /api/v1/backups", a.requireController(a.backupList))
	m.HandleFunc("POST /api/v1/backups", a.requireController(a.backupCreate))
	m.HandleFunc("POST /api/v1/backups/import", a.requireController(a.backupImport))
	m.HandleFunc("DELETE /api/v1/backups/{id}", a.requireController(a.backupDelete))
	m.HandleFunc("POST /api/v1/backups/{id}/restore", a.requireController(a.backupRestore))
	m.HandleFunc("GET /api/v1/backups/{id}/download", a.requireController(a.backupDownload))
	m.HandleFunc("POST /api/v1/hosts/pair", a.requireController(a.pairAgent))
	m.HandleFunc("DELETE /api/v1/hosts/{id}", a.requireController(a.removeAgent))
	m.HandleFunc("/api/v1/hosts/{host}/proxy/{path...}", a.requireController(a.proxyAgent))
	m.HandleFunc("GET /api/v1/groups", a.requireController(a.groupsList))
	m.HandleFunc("POST /api/v1/groups", a.requireController(a.groupCreate))
	m.HandleFunc("GET /api/v1/groups/{id}", a.requireController(a.groupGet))
	m.HandleFunc("PUT /api/v1/groups/{id}", a.requireController(a.groupUpdate))
	m.HandleFunc("DELETE /api/v1/groups/{id}", a.requireController(a.groupDelete))
	m.HandleFunc("POST /api/v1/groups/{id}/{action}", a.requireController(a.groupAction))
	m.HandleFunc("GET /api/v1/containers", a.requireController(a.containers))
	m.HandleFunc("GET /api/v1/containers/stats", a.requireController(a.containerStatsBatch))
	m.HandleFunc("POST /api/v1/containers", a.requireController(a.containerCreate))
	m.HandleFunc("POST /api/v1/containers/preflight", a.requireController(a.containerPreflight))
	m.HandleFunc("PUT /api/v1/containers/{id}", a.requireController(a.containerEdit))
	m.HandleFunc("GET /api/v1/containers/{id}", a.requireController(a.containerInspect))
	m.HandleFunc("GET /api/v1/containers/{id}/delete-plan", a.requireController(a.containerDeletePlan))
	m.HandleFunc("DELETE /api/v1/containers/{id}", a.requireController(a.containerDelete))
	m.HandleFunc("POST /api/v1/containers/{id}/adopt", a.requireController(a.containerAdopt))
	m.HandleFunc("POST /api/v1/containers/{id}/{action}", a.requireController(a.containerAction))
	m.HandleFunc("GET /api/v1/containers/{id}/logs", a.requireController(a.containerLogs))
	m.HandleFunc("GET /api/v1/containers/{id}/stats", a.requireController(a.containerStats))
	m.HandleFunc("GET /api/v1/containers/{id}/processes", a.requireController(a.containerProcesses))
	m.HandleFunc("GET /api/v1/containers/{id}/diagnostics", a.requireController(a.containerDiagnostics))
	m.HandleFunc("GET /api/v1/containers/{id}/files", a.requireController(a.containerFiles))
	m.HandleFunc("GET /api/v1/containers/{id}/files/content", a.requireController(a.containerFileGet))
	m.HandleFunc("PUT /api/v1/containers/{id}/files/content", a.requireController(a.containerFilePut))
	m.HandleFunc("GET /api/v1/containers/{id}/files/download", a.requireController(a.containerFileDownload))
	m.HandleFunc("POST /api/v1/containers/{id}/convert-compose", a.requireController(a.containerConvertCompose))
	m.HandleFunc("PUT /api/v1/containers/{id}/compose-image", a.requireController(a.containerExternalComposeImage))
	m.HandleFunc("GET /api/v1/containers/{id}/terminal", a.requireController(a.containerTerminal))
	m.HandleFunc("GET /api/v1/images", a.requireController(a.images))
	m.HandleFunc("POST /api/v1/images/pull", a.requireController(a.imagePull))
	m.HandleFunc("GET /api/v1/images/{id}", a.requireController(a.imageInspect))
	m.HandleFunc("GET /api/v1/images/{id}/history", a.requireController(a.imageHistory))
	m.HandleFunc("DELETE /api/v1/images/{id}", a.requireController(a.imageDelete))
	m.HandleFunc("GET /api/v1/volumes", a.requireController(a.volumes))
	m.HandleFunc("POST /api/v1/volumes", a.requireController(a.volumeCreate))
	m.HandleFunc("GET /api/v1/volumes/{name}", a.requireController(a.volumeInspect))
	m.HandleFunc("GET /api/v1/volumes/{name}/size", a.requireController(a.volumeSize))
	m.HandleFunc("DELETE /api/v1/volumes/{name}", a.requireController(a.volumeDelete))
	m.HandleFunc("GET /api/v1/volumes/{name}/files", a.requireController(a.volumeFiles))
	m.HandleFunc("GET /api/v1/volumes/{name}/file", a.requireController(a.volumeDownload))
	m.HandleFunc("PUT /api/v1/volumes/{name}/file", a.requireController(a.volumeWrite))
	m.HandleFunc("POST /api/v1/volumes/{name}/upload", a.requireController(a.volumeUpload))
	m.HandleFunc("GET /api/v1/volumes/{name}/archive", a.requireController(a.volumeArchive))
	m.HandleFunc("POST /api/v1/volumes/{name}/mkdir", a.requireController(a.volumeMkdir))
	m.HandleFunc("DELETE /api/v1/volumes/{name}/file", a.requireController(a.volumeFileDelete))
	m.HandleFunc("GET /api/v1/networks", a.requireController(a.networks))
	m.HandleFunc("POST /api/v1/networks", a.requireController(a.networkCreate))
	m.HandleFunc("GET /api/v1/networks/{id}", a.requireController(a.networkInspect))
	m.HandleFunc("DELETE /api/v1/networks/{id}", a.requireController(a.networkDelete))
	m.HandleFunc("POST /api/v1/networks/{id}/connect", a.requireController(a.networkConnect))
	m.HandleFunc("POST /api/v1/networks/{id}/disconnect", a.requireController(a.networkDisconnect))
	m.HandleFunc("GET /api/v1/projects", a.requireController(a.projectList))
	m.HandleFunc("POST /api/v1/projects/import", a.requireController(a.projectImport))
	m.HandleFunc("POST /api/v1/projects", a.requireController(a.projectSave))
	m.HandleFunc("POST /api/v1/projects/validate", a.requireController(a.projectValidateContent))
	m.HandleFunc("GET /api/v1/projects/{name}", a.requireController(a.projectGet))
	m.HandleFunc("GET /api/v1/projects/{name}/files", a.requireController(a.projectFiles))
	m.HandleFunc("GET /api/v1/projects/{name}/file", a.requireController(a.projectFileGet))
	m.HandleFunc("PUT /api/v1/projects/{name}/file", a.requireController(a.projectFilePut))
	m.HandleFunc("DELETE /api/v1/projects/{name}/file", a.requireController(a.projectFileDelete))
	m.HandleFunc("POST /api/v1/projects/{name}/mkdir", a.requireController(a.projectMkdir))
	m.HandleFunc("POST /api/v1/projects/{name}/rename", a.requireController(a.projectRename))
	m.HandleFunc("POST /api/v1/projects/{name}/upload", a.requireController(a.projectUpload))
	m.HandleFunc("GET /api/v1/projects/{name}/download", a.requireController(a.projectDownload))
	m.HandleFunc("GET /api/v1/projects/{name}/analysis", a.requireController(a.projectAnalysis))
	m.HandleFunc("GET /api/v1/projects/{name}/status", a.requireController(a.projectStatus))
	m.HandleFunc("GET /api/v1/projects/{name}/diagnostics", a.requireController(a.projectDiagnostics))
	m.HandleFunc("POST /api/v1/projects/{name}/build", a.requireController(a.projectBuild))
	m.HandleFunc("GET /api/v1/projects/{name}/archive", a.requireController(a.projectArchive))
	m.HandleFunc("PUT /api/v1/projects/{name}/compose-file", a.requireController(a.projectComposeFile))
	m.HandleFunc("GET /api/v1/projects/{name}/file-revisions", a.requireController(a.projectFileRevisions))
	m.HandleFunc("GET /api/v1/projects/{name}/file-revisions/{revision}", a.requireController(a.projectFileRevisionGet))
	m.HandleFunc("POST /api/v1/projects/{name}/file-revisions/{revision}/restore", a.requireController(a.projectFileRevisionRestore))
	m.HandleFunc("GET /api/v1/projects/{name}/revisions", a.requireController(a.projectRevisions))
	m.HandleFunc("GET /api/v1/projects/{name}/revisions/{revision}", a.requireController(a.projectRevisionGet))
	m.HandleFunc("POST /api/v1/projects/{name}/revisions/{revision}/restore", a.requireController(a.projectRevisionRestore))
	m.HandleFunc("PUT /api/v1/projects/{name}", a.requireController(a.projectSaveNamed))
	m.HandleFunc("DELETE /api/v1/projects/{name}", a.requireController(a.projectDelete))
	m.HandleFunc("POST /api/v1/projects/{name}/{action}", a.requireController(a.projectAction))
	m.HandleFunc("GET /api/v1/projects/{name}/logs", a.requireController(a.projectLogs))
	m.HandleFunc("GET /api/v1/registries", a.requireController(a.registries))
	m.HandleFunc("POST /api/v1/registries", a.requireController(a.registrySave))
	m.HandleFunc("PUT /api/v1/registries/{id}", a.requireController(a.registrySave))
	m.HandleFunc("DELETE /api/v1/registries/{id}", a.requireController(a.registryDelete))
	m.HandleFunc("POST /api/v1/registries/test", a.requireController(a.registryTest))
	m.HandleFunc("GET /api/v1/api-keys", a.requireController(a.apiKeys))
	m.HandleFunc("POST /api/v1/api-keys", a.requireController(a.apiKeyCreate))
	m.HandleFunc("DELETE /api/v1/api-keys/{id}", a.requireController(a.apiKeyDelete))
	m.HandleFunc("GET /api/v1/activity", a.requireController(a.activity))
	m.HandleFunc("GET /api/v1/openapi", func(w http.ResponseWriter, r *http.Request) {
		b, err := webassets.OpenAPI()
		if err != nil {
			errorJSON(w, 500, "openapi_error", err.Error())
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write(b)
	})
	m.HandleFunc("/", a.serveSPA)
}

func (a *App) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self' ws: wss:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

func (a *App) getSetup(w http.ResponseWriter, r *http.Request) {
	role := a.db.Role()
	instanceName, _, _ := a.db.GetSetting("instance_name")
	resp := map[string]any{
		"setup":               role != "",
		"language":            a.requestLanguage(r),
		"role":                role,
		"version":             version.Version,
		"instance_name":       instanceName,
		"local_code_required": role == "",
	}
	if role == "agent" {
		id, _, _ := a.db.GetSetting("agent_id")
		master, _, _ := a.db.GetSetting("master_url")
		paired := master != ""
		a.agentStateMu.RLock()
		listening, listenErr := a.agentListening, a.agentListenError
		a.agentStateMu.RUnlock()
		resp["agent_id"] = id
		resp["paired"] = paired
		resp["local_code_required"] = !paired
		resp["agent_management_active"] = listening
		if listenErr != "" {
			resp["agent_management_error"] = listenErr
		}
		if !paired {
			resp["agent_listen_port"] = agentListenPort(a.cfg.AgentListen)
			if published := a.agentPublishedPort(); published > 0 {
				resp["agent_published_port"] = published
			}
		} else {
			resp["master_url"] = master
		}
	}
	writeJSON(w, resp)
}

func (a *App) postSetup(w http.ResponseWriter, r *http.Request) {
	a.setupMu.Lock()
	defer a.setupMu.Unlock()
	if a.db.IsSetup() {
		errorJSON(w, 409, "already_setup", "ZentContainer is already configured")
		return
	}
	if !sameOriginRequest(r) {
		errorJSON(w, 403, "cross_site_request", "Cross-site request rejected")
		return
	}
	var in struct {
		Role         string `json:"role"`
		InstanceName string `json:"instanceName"`
		Username     string `json:"username"`
		Password     string `json:"password"`
		Language     string `json:"language"`
		LocalCode    string `json:"local_code"`
	}
	if !decodeJSONLimit(w, r, &in, 16<<10) {
		return
	}
	if !a.verifyLocalAccessCode(in.LocalCode) {
		time.Sleep(250 * time.Millisecond)
		errorJSON(w, 401, "invalid_local_code", "The local setup code is invalid. Read it from the ZentContainer container logs.")
		return
	}
	in.Role = strings.ToLower(strings.TrimSpace(in.Role))
	if in.Language != "" && in.Language != "de" && in.Language != "en" {
		errorJSON(w, 400, "invalid_language", "language must be de or en")
		return
	}
	in.Language = normalizeUILanguage(in.Language)
	if in.Role != "controller" && in.Role != "agent" {
		errorJSON(w, 400, "invalid_role", "role must be controller or agent")
		return
	}
	in.InstanceName = strings.TrimSpace(in.InstanceName)
	if in.InstanceName == "" {
		in.InstanceName = "ZentContainer"
	}
	if len(in.InstanceName) > 120 {
		errorJSON(w, 400, "invalid_instance_name", "instance name must not exceed 120 characters")
		return
	}
	if in.Role == "controller" {
		in.Username = strings.TrimSpace(in.Username)
		if in.Username == "" || len(in.Username) > 128 {
			errorJSON(w, 400, "invalid_username", "username is required and must not exceed 128 characters")
			return
		}
		h, err := auth.HashPassword(in.Password)
		if err != nil {
			errorJSON(w, 400, "weak_password", err.Error())
			return
		}
		if err := agentsec.EnsureControllerPKI(a.cfg.CertificatesDir()); err != nil {
			errorJSON(w, 500, "setup_failed", err.Error())
			return
		}
		userID, err := a.db.CreateUserWithLanguage(in.Username, h, true, in.Language)
		if err != nil {
			errorJSON(w, 500, "setup_failed", err.Error())
			return
		}
		if err := a.db.SetSettings(map[string]string{
			"instance_name": in.InstanceName,
			"ui_language":   in.Language,
			"role":          in.Role,
		}); err != nil {
			_ = a.db.DeleteUser(userID)
			errorJSON(w, 500, "setup_failed", err.Error())
			return
		}
		a.removeLocalAccessCode()
	} else {
		id, err := randomHex(8)
		if err != nil {
			errorJSON(w, 500, "setup_failed", err.Error())
			return
		}
		if err := agentsec.EnsureAgentServerCert(a.cfg.CertificatesDir()); err != nil {
			errorJSON(w, 500, "setup_failed", err.Error())
			return
		}
		agentID := "zc-agent-" + id
		if err := a.resetAgentPairingCode(); err != nil {
			errorJSON(w, 500, "setup_failed", err.Error())
			return
		}
		if err := a.db.SetSettings(map[string]string{
			"agent_id":      agentID,
			"instance_name": in.InstanceName,
			"ui_language":   in.Language,
			"role":          in.Role,
		}); err != nil {
			errorJSON(w, 500, "setup_failed", err.Error())
			return
		}
	}
	a.db.AddAudit("system", "setup.completed", "system", "role="+in.Role)
	if in.Role == "agent" {
		a.startAgentServer()
	}
	writeJSONStatus(w, 201, map[string]any{"ok": true, "role": in.Role})
}

func (a *App) agentStatus(w http.ResponseWriter, r *http.Request) {
	if a.db.Role() != "agent" {
		errorJSON(w, 404, "not_agent", "This instance is not an agent")
		return
	}
	a.getSetup(w, r)
}
func (a *App) agentPairingCode(w http.ResponseWriter, r *http.Request) {
	if a.db.Role() != "agent" {
		errorJSON(w, 404, "not_agent", "This instance is not an agent")
		return
	}
	if !sameOriginRequest(r) {
		errorJSON(w, 403, "cross_site_request", "Cross-site request rejected")
		return
	}
	var in struct {
		LocalCode string `json:"local_code"`
	}
	if !decodeJSONLimit(w, r, &in, 8<<10) {
		return
	}
	if !a.verifyLocalAccessCode(in.LocalCode) {
		time.Sleep(250 * time.Millisecond)
		errorJSON(w, 401, "invalid_local_code", "The local access code is invalid")
		return
	}
	master, _, err := a.db.GetSetting("master_url")
	if err != nil {
		errorJSON(w, 500, "agent_state_error", err.Error())
		return
	}
	if master != "" {
		errorJSON(w, 409, "already_paired", "Agent is already paired")
		return
	}
	code, _, err := a.db.GetSetting("pairing_code")
	if err != nil {
		errorJSON(w, 500, "agent_state_error", err.Error())
		return
	}
	if code == "" {
		errorJSON(w, 503, "pairing_code_unavailable", "Pairing code is not available")
		return
	}
	writeJSON(w, map[string]any{"pairing_code": code})
}

func (a *App) agentResetPairing(w http.ResponseWriter, r *http.Request) {
	if a.db.Role() != "agent" {
		errorJSON(w, 404, "not_agent", "This instance is not an agent")
		return
	}
	if !sameOriginRequest(r) {
		errorJSON(w, 403, "cross_site_request", "Cross-site request rejected")
		return
	}
	var in struct {
		LocalCode string `json:"local_code"`
	}
	if !decodeJSONLimit(w, r, &in, 8<<10) {
		return
	}
	if !a.verifyLocalAccessCode(in.LocalCode) {
		time.Sleep(250 * time.Millisecond)
		errorJSON(w, 401, "invalid_local_code", "The local access code is invalid")
		return
	}
	a.pairingMu.Lock()
	defer a.pairingMu.Unlock()
	if err := a.resetAgentPairingCode(); err != nil {
		errorJSON(w, 500, "pairing_reset_failed", err.Error())
		return
	}
	a.db.AddAudit("local", "agent.pairing_reset", "system", "local access code")
	writeJSON(w, map[string]any{"ok": true})
}

func authNoStore(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		fn(w, r)
	}
}
func (a *App) login(w http.ResponseWriter, r *http.Request) {
	if a.db.Role() != "controller" {
		errorJSON(w, 403, "agent_mode", "Agent instances do not provide local administration")
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Language string `json:"language"`
	}
	if !decodeJSONLimit(w, r, &in, 16<<10) {
		return
	}
	if len(in.Username) > 128 || len(in.Password) > auth.MaxPasswordBytes {
		time.Sleep(250 * time.Millisecond)
		errorJSON(w, 401, "invalid_credentials", "Invalid username or password")
		return
	}
	if retry := a.loginRetryAfter(r, in.Username); retry > 0 {
		setRetryAfter(w, retry)
		errorJSON(w, 429, "login_rate_limited", "Too many failed login attempts. Try again later.")
		return
	}
	u, ok, err := a.db.UserByName(in.Username)
	if err != nil {
		errorJSON(w, 503, "auth_backend_unavailable", "Authentication is temporarily unavailable")
		return
	}
	if !ok || !auth.VerifyPassword(u.PasswordHash, in.Password) {
		retry := a.recordLoginFailure(r, in.Username)
		if retry > 0 {
			setRetryAfter(w, retry)
		}
		time.Sleep(250 * time.Millisecond)
		errorJSON(w, 401, "invalid_credentials", "Invalid username or password")
		return
	}
	a.clearLoginFailures(r, in.Username)
	if in.Language != "" {
		if in.Language != "de" && in.Language != "en" {
			errorJSON(w, 400, "invalid_language", "language must be de or en")
			return
		}
		if err := a.db.UpdateUserLanguage(u.ID, in.Language); err != nil {
			errorJSON(w, 503, "settings_unavailable", "Language preference could not be saved")
			return
		}
		u.Language = in.Language
	}
	if auth.PasswordNeedsRehash(u.PasswordHash) {
		upgradedHash, hashErr := auth.HashPassword(in.Password)
		if hashErr != nil {
			errorJSON(w, 503, "auth_upgrade_failed", "Authentication storage upgrade failed")
			return
		}
		if err := a.db.UpdateUserPasswordHash(u.ID, upgradedHash); err != nil {
			errorJSON(w, 503, "auth_backend_unavailable", "Authentication storage upgrade failed")
			return
		}
		u.PasswordHash = upgradedHash
		a.db.AddAudit(u.Username, "auth.password_hash_upgraded", "system", "PBKDF2 work factor upgraded")
	}
	token, err := auth.RandomToken(32)
	if err != nil {
		errorJSON(w, 500, "login_failed", err.Error())
		return
	}
	expires := time.Now().Add(a.cfg.SessionTTL)
	if err := a.db.CreateSession(auth.TokenHash(token), u.ID, expires.Unix()); err != nil {
		errorJSON(w, 500, "login_failed", err.Error())
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "zc_session", Value: token, Path: "/", HttpOnly: true, Secure: a.cfg.CookieSecure, SameSite: http.SameSiteStrictMode, Expires: expires})
	a.setLanguageCookie(w, u.Language)
	a.db.AddAudit(u.Username, "auth.login", "system", "")
	writeJSON(w, map[string]any{"ok": true, "username": u.Username, "language": normalizeUILanguage(u.Language)})
}

func (a *App) changePassword(w http.ResponseWriter, r *http.Request) {
	ac, ok, err := a.authenticate(r)
	if err != nil {
		errorJSON(w, 503, "auth_backend_unavailable", "Session validation is temporarily unavailable")
		return
	}
	if !ok || ac.IsAPI || ac.User == nil || !ac.User.IsAdmin {
		errorJSON(w, 403, "interactive_session_required", "An administrator browser session is required")
		return
	}
	var in struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !decodeJSONLimit(w, r, &in, 16<<10) {
		return
	}
	if len(in.CurrentPassword) > auth.MaxPasswordBytes {
		errorJSON(w, 403, "invalid_current_password", "Current password is invalid")
		return
	}
	if !auth.VerifyPassword(ac.User.PasswordHash, in.CurrentPassword) {
		time.Sleep(250 * time.Millisecond)
		errorJSON(w, 403, "invalid_current_password", "Current password is invalid")
		return
	}
	newHash, err := auth.HashPassword(in.NewPassword)
	if err != nil {
		errorJSON(w, 400, "weak_password", err.Error())
		return
	}
	if auth.VerifyPassword(ac.User.PasswordHash, in.NewPassword) {
		errorJSON(w, 400, "password_unchanged", "New password must be different from the current password")
		return
	}
	if err := a.db.ChangeUserPassword(ac.User.ID, newHash, ac.SessionHash); err != nil {
		errorJSON(w, 500, "password_change_failed", err.Error())
		return
	}
	a.sessionMu.Lock()
	a.sessionCache = map[string]cachedSession{}
	a.sessionMu.Unlock()
	a.db.AddAudit(ac.Name, "auth.password_changed", "system", "other sessions revoked")
	writeJSON(w, map[string]any{"ok": true, "other_sessions_revoked": true})
}

func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("zc_session"); err == nil {
		hash := auth.TokenHash(c.Value)
		_ = a.db.DeleteSession(hash)
		a.sessionMu.Lock()
		delete(a.sessionCache, hash)
		a.sessionMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "zc_session", Value: "", Path: "/", HttpOnly: true, Secure: a.cfg.CookieSecure, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	writeJSON(w, map[string]any{"ok": true})
}
func (a *App) me(w http.ResponseWriter, r *http.Request) {
	ac, ok, err := a.authenticate(r)
	if err != nil {
		errorJSON(w, 503, "auth_backend_unavailable", "Session validation is temporarily unavailable")
		return
	}
	if !ok {
		w.Header().Set("X-ZC-Auth-Required", "session")
		errorJSON(w, 401, "unauthorized", "Authentication required")
		return
	}
	language := a.requestLanguage(r)
	if ac.User != nil {
		language = normalizeUILanguage(ac.User.Language)
	}
	a.setLanguageCookie(w, language)
	writeJSON(w, map[string]any{"name": ac.Name, "api": ac.IsAPI, "admin": ac.User != nil && ac.User.IsAdmin, "language": language})
}

func (a *App) authenticate(r *http.Request) (actor, bool, error) {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer zc_live_") {
		parts := strings.SplitN(strings.TrimPrefix(h, "Bearer zc_live_"), "_", 2)
		if len(parts) == 2 {
			k, ok, err := a.db.APIKeyByPrefix(parts[0])
			if err != nil {
				return actor{}, false, err
			}
			if ok && constantString(auth.TokenHash(parts[1]), k.SecretHash) {
				a.db.TouchAPIKey(k.ID)
				sc := map[string]bool{}
				for _, scope := range strings.Split(k.Scopes, ",") {
					sc[strings.TrimSpace(scope)] = true
				}
				return actor{Name: "api:" + k.Name, IsAPI: true, Scopes: sc}, true, nil
			}
		}
	}
	c, err := r.Cookie("zc_session")
	if err != nil {
		return actor{}, false, nil
	}
	hash := auth.TokenHash(c.Value)
	a.sessionMu.Lock()
	if cached, ok := a.sessionCache[hash]; ok && time.Since(cached.At) < 10*time.Second && cached.Actor.SessionExpires > time.Now().Unix() {
		ac := cached.Actor
		a.sessionMu.Unlock()
		return ac, true, nil
	}
	a.sessionMu.Unlock()
	u, expires, ok, err := a.db.SessionUserWithExpiry(hash)
	if err != nil {
		return actor{}, false, err
	}
	if !ok {
		a.sessionMu.Lock()
		delete(a.sessionCache, hash)
		a.sessionMu.Unlock()
		return actor{}, false, nil
	}
	ac := actor{Name: u.Username, User: &u, Scopes: map[string]bool{"*": true}, SessionHash: hash, SessionToken: c.Value, SessionExpires: expires}
	a.sessionMu.Lock()
	a.sessionCache[hash] = cachedSession{Actor: ac, At: time.Now()}
	a.sessionMu.Unlock()
	return ac, true, nil
}

func (a *App) refreshSession(w http.ResponseWriter, ac actor) {
	if ac.IsAPI || ac.SessionHash == "" || a.cfg.SessionTTL <= 0 {
		return
	}
	now := time.Now()
	// Refresh only in the second half of the TTL so normal API polling does not
	// write to SQLite on every request while still keeping active sessions alive.
	if time.Unix(ac.SessionExpires, 0).Sub(now) > a.cfg.SessionTTL/2 {
		return
	}
	expires := now.Add(a.cfg.SessionTTL)
	if err := a.db.ExtendSession(ac.SessionHash, expires.Unix()); err != nil {
		return
	}
	ac.SessionExpires = expires.Unix()
	a.sessionMu.Lock()
	a.sessionCache[ac.SessionHash] = cachedSession{Actor: ac, At: time.Now()}
	a.sessionMu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "zc_session", Value: ac.SessionToken, Path: "/", HttpOnly: true, Secure: a.cfg.CookieSecure, SameSite: http.SameSiteStrictMode, Expires: expires})
}
func constantString(a1, b1 string) bool {
	if len(a1) != len(b1) {
		return false
	}
	var x byte
	for i := 0; i < len(a1); i++ {
		x |= a1[i] ^ b1[i]
	}
	return x == 0
}
func (a *App) require(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ac, ok, authErr := a.authenticate(r)
		if authErr != nil {
			errorJSON(w, 503, "auth_backend_unavailable", "Session validation is temporarily unavailable")
			return
		}
		if !ok {
			w.Header().Set("X-ZC-Auth-Required", "session")
			errorJSON(w, 401, "unauthorized", "Authentication required")
			return
		}
		if !ac.IsAPI && !sameOriginRequest(r) {
			errorJSON(w, 403, "cross_site_request", "Cross-site request rejected")
			return
		}
		a.refreshSession(w, ac)
		fn(w, r)
	}
}
func (a *App) requireController(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.db.Role() != "controller" {
			errorJSON(w, 403, "controller_required", "This endpoint is only available on a controller")
			return
		}
		ac, ok, authErr := a.authenticate(r)
		if authErr != nil {
			errorJSON(w, 503, "auth_backend_unavailable", "Session validation is temporarily unavailable")
			return
		}
		if !ok {
			w.Header().Set("X-ZC-Auth-Required", "session")
			errorJSON(w, 401, "unauthorized", "Authentication required")
			return
		}
		if !ac.IsAPI && !sameOriginRequest(r) {
			errorJSON(w, 403, "cross_site_request", "Cross-site request rejected")
			return
		}
		a.refreshSession(w, ac)
		if ac.IsAPI {
			for _, scope := range requiredScopes(r) {
				if !ac.Scopes["*"] && !ac.Scopes[scope] {
					errorJSON(w, 403, "insufficient_scope", "API key requires scope: "+scope)
					return
				}
			}
		}
		fn(w, r)
	}
}

func requiredScopes(r *http.Request) []string {
	if r.Pattern == "/api/v1/hosts/{host}/proxy/{path...}" {
		return resourceRequiredScopes(r.Method, "/"+strings.TrimPrefix(r.PathValue("path"), "/"), r.URL.Query())
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	return resourceRequiredScopes(r.Method, path, r.URL.Query())
}

func resourceRequiredScopes(method, path string, query url.Values) []string {
	clean := strings.Trim(strings.TrimSpace(path), "/")
	if clean == "" {
		return []string{"admin"}
	}
	seg := strings.Split(clean, "/")
	switch seg[0] {
	case "system", "dashboard", "host-metrics", "hosts", "events":
		if seg[0] == "hosts" && len(seg) > 1 {
			return []string{"admin"}
		}
		return []string{"hosts.read"}
	case "hardware":
		if len(seg) == 2 && seg[1] == "devices" && method == http.MethodGet {
			return []string{"hosts.read"}
		}
	case "resources":
		if len(seg) == 2 && seg[1] == "map" && method == http.MethodGet {
			return []string{"hosts.read"}
		}
	case "settings":
		return []string{"admin"}
	case "account":
		return []string{"admin"}
	case "storage":
		if method == http.MethodGet {
			return []string{"hosts.read"}
		}
		if method == http.MethodPost && len(seg) == 2 && seg[1] == "cleanup" {
			return []string{"admin"}
		}
	case "backups":
		if method == http.MethodGet {
			return []string{"volumes.read", "projects.read"}
		}
		return []string{"admin"}
	case "groups":
		if len(seg) == 1 {
			if method == http.MethodGet {
				return []string{"groups.read"}
			}
			if method == http.MethodPost {
				return []string{"groups.write"}
			}
		}
		if len(seg) == 2 {
			if method == http.MethodGet {
				return []string{"groups.read"}
			}
			if method == http.MethodPut || method == http.MethodDelete {
				return []string{"groups.write"}
			}
		}
		if len(seg) == 3 && method == http.MethodPost {
			return []string{"groups.control"}
		}
	case "containers":
		if len(seg) == 1 {
			if method == http.MethodGet {
				return []string{"containers.read"}
			}
			if method == http.MethodPost {
				return []string{"containers.create"}
			}
		}
		if len(seg) == 2 && seg[1] == "preflight" && method == http.MethodPost {
			return []string{"containers.read"}
		}
		if len(seg) == 2 {
			switch method {
			case http.MethodGet:
				return []string{"containers.read"}
			case http.MethodPut:
				return []string{"containers.control"}
			case http.MethodDelete:
				scopes := []string{"containers.delete"}
				if query.Get("remove_volumes") == "true" {
					scopes = append(scopes, "volumes.write")
				}
				if query.Get("remove_image") == "true" {
					scopes = append(scopes, "images.delete")
				}
				if query.Get("remove_networks") == "true" {
					scopes = append(scopes, "networks.write")
				}
				return scopes
			}
		}
		if len(seg) >= 3 {
			sub := seg[2]
			switch sub {
			case "delete-plan":
				if method == http.MethodGet {
					return []string{"containers.read", "images.read", "volumes.read", "networks.read"}
				}
			case "adopt":
				if method == http.MethodPost {
					return []string{"containers.control"}
				}
			case "terminal":
				if method == http.MethodGet {
					return []string{"containers.terminal"}
				}
			case "convert-compose":
				if method == http.MethodPost {
					return []string{"containers.read", "projects.write"}
				}
			case "compose-image":
				if method == http.MethodPut {
					return []string{"containers.control", "images.pull"}
				}
			case "files":
				if method == http.MethodPut && len(seg) >= 4 && seg[3] == "content" {
					return []string{"containers.control"}
				}
				if method == http.MethodGet {
					return []string{"containers.read"}
				}
			case "logs", "stats", "processes", "diagnostics":
				if method == http.MethodGet {
					return []string{"containers.read"}
				}
			default:
				if method == http.MethodPost {
					switch sub {
					case "update-check":
						return []string{"containers.read", "images.read"}
					case "update":
						return []string{"containers.control", "images.pull"}
					default:
						return []string{"containers.control"}
					}
				}
			}
		}
	case "images":
		if len(seg) == 1 && method == http.MethodGet {
			return []string{"images.read"}
		}
		if len(seg) >= 2 && seg[1] == "pull" && method == http.MethodPost {
			return []string{"images.pull"}
		}
		if method == http.MethodGet {
			return []string{"images.read"}
		}
		if method == http.MethodDelete {
			return []string{"images.delete"}
		}
	case "volumes":
		if len(seg) == 1 {
			if method == http.MethodGet {
				return []string{"volumes.read"}
			}
			if method == http.MethodPost {
				return []string{"volumes.write"}
			}
		}
		if len(seg) == 2 {
			if method == http.MethodGet {
				return []string{"volumes.read"}
			}
			if method == http.MethodDelete {
				return []string{"volumes.write"}
			}
		}
		if len(seg) >= 3 {
			switch seg[2] {
			case "size":
				if method == http.MethodGet {
					return []string{"volumes.read"}
				}
			case "files", "file", "archive":
				if method == http.MethodGet {
					return []string{"volumes.files.read"}
				}
				if method == http.MethodPut || method == http.MethodDelete {
					return []string{"volumes.files.write"}
				}
			case "upload", "mkdir":
				if method == http.MethodPost {
					return []string{"volumes.files.write"}
				}
			}
		}
	case "networks":
		if method == http.MethodGet {
			return []string{"networks.read"}
		}
		return []string{"networks.write"}
	case "projects":
		if len(seg) == 1 {
			if method == http.MethodGet {
				return []string{"projects.read"}
			}
			if method == http.MethodPost {
				return []string{"projects.write"}
			}
		}
		if len(seg) == 2 && seg[1] == "validate" && method == http.MethodPost {
			return []string{"projects.read"}
		}
		if len(seg) == 2 && seg[1] == "import" && method == http.MethodPost {
			return []string{"projects.write"}
		}
		if len(seg) == 2 {
			switch method {
			case http.MethodGet:
				return []string{"projects.read"}
			case http.MethodPut, http.MethodDelete:
				return []string{"projects.write"}
			}
		}
		if len(seg) >= 3 {
			sub := seg[2]
			switch sub {
			case "build":
				if method == http.MethodPost {
					return []string{"projects.deploy", "images.pull"}
				}
			case "compose-file":
				if method == http.MethodPut {
					return []string{"projects.write"}
				}
			case "file":
				if method == http.MethodPut || method == http.MethodDelete {
					return []string{"projects.write"}
				}
				if method == http.MethodGet {
					return []string{"projects.read"}
				}
			case "mkdir", "rename", "upload":
				if method == http.MethodPost {
					return []string{"projects.write"}
				}
			case "file-revisions", "revisions":
				if method == http.MethodPost && len(seg) >= 5 && seg[len(seg)-1] == "restore" {
					return []string{"projects.write"}
				}
				if method == http.MethodGet {
					return []string{"projects.read"}
				}
			case "files", "download", "analysis", "status", "diagnostics", "archive", "logs":
				if method == http.MethodGet {
					return []string{"projects.read"}
				}
			default:
				if method == http.MethodPost {
					if sub == "validate" || sub == "config" {
						return []string{"projects.read"}
					}
					return []string{"projects.deploy"}
				}
			}
		}
	case "registries", "api-keys":
		return []string{"admin"}
	case "activity":
		return []string{"audit.read"}
	}
	return []string{"admin"}
}

var validAPIScopes = map[string]bool{
	"hosts.read":      true,
	"containers.read": true, "containers.control": true, "containers.create": true, "containers.delete": true, "containers.terminal": true,
	"groups.read": true, "groups.write": true, "groups.control": true,
	"images.read": true, "images.pull": true, "images.delete": true,
	"volumes.read": true, "volumes.write": true, "volumes.files.read": true, "volumes.files.write": true,
	"networks.read": true, "networks.write": true,
	"projects.read": true, "projects.write": true, "projects.deploy": true,
	"audit.read": true, "admin": true,
}

func sameOriginRequest(r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return true
	}
	if strings.EqualFold(r.Header.Get("Sec-Fetch-Site"), "cross-site") {
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		return err == nil && strings.EqualFold(u.Host, r.Host)
	}
	return true
}
func (a *App) currentActor(r *http.Request) string {
	if a.db.Role() == "agent" {
		if v := strings.TrimSpace(r.Header.Get("X-ZC-Actor")); v != "" {
			return v
		}
	}
	ac, ok, err := a.authenticate(r)
	if err != nil || !ok {
		return "unknown"
	}
	return ac.Name
}

func (a *App) docker() (*dockerx.Client, error) {
	a.dockerMu.Lock()
	defer a.dockerMu.Unlock()
	if a.dockerClient != nil {
		return a.dockerClient, nil
	}
	d, err := dockerx.New(a.cfg.DockerSocket)
	if err != nil {
		a.dockerErr = err.Error()
		return nil, err
	}
	a.dockerClient = d
	a.dockerErr = ""
	return d, nil
}
func (a *App) system(w http.ResponseWriter, r *http.Request) {
	name, _, _ := a.db.GetSetting("instance_name")
	d, err := a.docker()
	data := map[string]any{"version": version.Version, "role": a.db.Role(), "instance_name": name, "docker_connected": err == nil, "docker_error": a.dockerErr, "data_dir": a.cfg.DataDir}
	if d != nil {
		data["docker_api"] = d.APIVersion
	}
	writeJSON(w, data)
}
func (a *App) dashboard(w http.ResponseWriter, r *http.Request) {
	d, err := a.docker()
	if err != nil {
		errorJSON(w, 503, "docker_unavailable", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	var (
		cs      []dockerx.ContainerSummary
		imgs    []dockerx.ImageSummary
		vols    []dockerx.Volume
		nets    []dockerx.Network
		info    json.RawMessage
		storage dockerStorageSummary
		wg      sync.WaitGroup
	)
	wg.Add(6)
	go func() { defer wg.Done(); cs, _ = d.Containers(ctx, true) }()
	go func() { defer wg.Done(); imgs, _ = d.Images(ctx) }()
	go func() { defer wg.Done(); vols, _ = d.Volumes(ctx) }()
	go func() { defer wg.Done(); nets, _ = d.Networks(ctx) }()
	go func() { defer wg.Done(); info, _ = d.Info(ctx) }()
	go func() { defer wg.Done(); storage = a.cachedDockerStorage(ctx, d) }()
	wg.Wait()
	running := 0
	stopped := 0
	for _, c := range cs {
		if isBackup(c) {
			continue
		}
		if c.State == "running" {
			running++
		} else {
			stopped++
		}
	}
	checks, _ := a.db.ListUpdateChecks()
	updates := 0
	for _, c := range checks {
		if c.Status == "update_available" {
			updates++
		}
	}
	writeJSON(w, map[string]any{"containers": map[string]int{"running": running, "stopped": stopped, "total": running + stopped}, "images": len(imgs), "volumes": len(vols), "networks": len(nets), "updates": updates, "update_checks": checks, "info": info, "storage": storage})
}

const hostMetricsFreshFor = 4 * time.Second

func (a *App) hostMetrics(w http.ResponseWriter, r *http.Request) {
	// Live host metrics are read directly from the read-only host /proc mount.
	// A short cache coalesces simultaneous dashboard/host-page requests while
	// still delivering a genuinely fresh sample on the normal five-second poll.
	a.metricsMu.Lock()
	cached := append([]byte(nil), a.metricsData...)
	age := time.Since(a.metricsAt)
	a.metricsMu.Unlock()
	if len(cached) > 0 && age < hostMetricsFreshFor {
		w.Header().Set("X-ZC-Metrics-Age", strconv.FormatInt(int64(age/time.Second), 10))
		writeRawJSON(w, cached)
		return
	}

	out, err := a.collectHostMetrics(r.Context())
	if err != nil {
		// Keep the last good sample visible when a single collection is delayed.
		if len(cached) > 0 {
			w.Header().Set("X-ZC-Metrics-Stale", "true")
			w.Header().Set("X-ZC-Metrics-Age", strconv.FormatInt(int64(age/time.Second), 10))
			writeRawJSON(w, cached)
			return
		}
		errorJSON(w, 502, "host_metrics_failed", err.Error())
		return
	}
	writeRawJSON(w, out)
}

func (a *App) collectHostMetrics(ctx context.Context) ([]byte, error) {
	a.metricsMu.Lock()
	if a.metricsRefreshing {
		a.metricsMu.Unlock()
		deadline := time.NewTimer(2 * time.Second)
		defer deadline.Stop()
		ticker := time.NewTicker(25 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-deadline.C:
				return nil, errors.New("host metrics collection is still running")
			case <-ticker.C:
				a.metricsMu.Lock()
				data := append([]byte(nil), a.metricsData...)
				running := a.metricsRefreshing
				a.metricsMu.Unlock()
				if len(data) > 0 {
					return data, nil
				}
				if !running {
					return nil, errors.New("host metrics collection failed")
				}
			}
		}
	}
	a.metricsRefreshing = true
	a.metricsMu.Unlock()
	return a.refreshHostMetrics(ctx)
}

func (a *App) refreshHostMetrics(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		a.metricsMu.Lock()
		a.metricsRefreshing = false
		a.metricsMu.Unlock()
		return nil, ctx.Err()
	default:
	}
	metrics, err := volumehelper.CollectHostMetrics("/host-proc", "", "/host-hostname", "/host-os-release")
	if err != nil {
		a.metricsMu.Lock()
		a.metricsRefreshing = false
		a.metricsMu.Unlock()
		return nil, err
	}
	out, err := json.Marshal(metrics)
	if err != nil {
		a.metricsMu.Lock()
		a.metricsRefreshing = false
		a.metricsMu.Unlock()
		return nil, err
	}
	a.metricsMu.Lock()
	a.metricsRefreshing = false
	a.metricsData = append(a.metricsData[:0], out...)
	a.metricsAt = time.Now()
	a.metricsMu.Unlock()
	return append([]byte(nil), out...), nil
}

func (a *App) refreshHostMetricsBackground() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _ = a.collectHostMetrics(ctx)
}

func (a *App) hosts(w http.ResponseWriter, r *http.Request) {
	name, _, _ := a.db.GetSetting("instance_name")
	d, err := a.docker()
	api := ""
	if d != nil {
		api = d.APIVersion
	}
	// Do not synchronously probe remote agents here. The WebUI loads every host
	// independently so one unreachable machine can never delay the others.
	out := []any{map[string]any{"id": "local", "name": name, "type": "controller", "online": err == nil, "docker_api": api, "version": version.Version}}
	agents, dbErr := a.db.ListAgents()
	if dbErr != nil {
		errorJSON(w, 500, "db_error", dbErr.Error())
		return
	}
	for _, ag := range agents {
		out = append(out, map[string]any{"id": ag.ID, "name": ag.Name, "type": "agent", "url": ag.URL, "version": ag.Version, "last_seen_at": ag.LastSeenAt})
	}
	writeJSON(w, out)
}

func isBackup(c dockerx.ContainerSummary) bool {
	for _, n := range c.Names {
		if strings.HasPrefix(n, "/zc-backup-") || strings.HasPrefix(n, "/.zc-backup-") {
			return true
		}
	}
	return c.Labels["io.zentcontainer.backup"] == "true"
}
func (a *App) containers(w http.ResponseWriter, r *http.Request) {
	d, err := a.docker()
	if err != nil {
		errorJSON(w, 503, "docker_unavailable", err.Error())
		return
	}
	v, err := d.Containers(r.Context(), true)
	if err != nil {
		errorJSON(w, 502, "docker_error", err.Error())
		return
	}
	pendingRows, _ := a.db.ListPendingContainerEdits()
	pending := map[string]bool{}
	for _, p := range pendingRows {
		pending[p.Name] = true
	}
	out := make([]dockerx.ContainerSummary, 0, len(v))
	for _, c := range v {
		if !isBackup(c) {
			name := strings.TrimPrefix(first(c.Names), "/")
			if pending[name] {
				if c.Labels == nil {
					c.Labels = map[string]string{}
				}
				c.Labels["io.zentcontainer.pending-edit"] = "true"
			}
			out = append(out, c)
		}
	}
	writeJSON(w, out)
}
func (a *App) containerInspect(w http.ResponseWriter, r *http.Request) {
	d, err := a.docker()
	if err != nil {
		errorJSON(w, 503, "docker_unavailable", err.Error())
		return
	}
	v, err := d.ContainerInspect(r.Context(), r.PathValue("id"))
	if err != nil {
		errorJSON(w, 502, "docker_error", err.Error())
		return
	}
	var data map[string]any
	if json.Unmarshal(v, &data) == nil {
		name := strings.TrimPrefix(asString(data["Name"]), "/")
		if a.db.IsContainerAdopted(name) {
			cfg, _ := data["Config"].(map[string]any)
			if cfg == nil {
				cfg = map[string]any{}
				data["Config"] = cfg
			}
			labels, _ := cfg["Labels"].(map[string]any)
			if labels == nil {
				labels = map[string]any{}
				cfg["Labels"] = labels
			}
			labels["io.zentcontainer.adopted"] = "true"
		}
		if pending, ok, _ := a.db.PendingContainerEdit(name); ok {
			var desired any
			if json.Unmarshal([]byte(pending.Payload), &desired) == nil {
				data["ZentContainerPendingEdit"] = desired
				data["ZentContainerPendingEditAt"] = pending.UpdatedAt
			}
		}
		writeJSON(w, data)
		return
	}
	writeRawJSON(w, v)
}
func (a *App) containerCreate(w http.ResponseWriter, r *http.Request) {
	var in containerInput
	if !decodeJSON(w, r, &in) {
		return
	}
	id, err := a.createManagedContainer(r.Context(), in, true)
	if err != nil {
		errorJSON(w, 502, "create_failed", err.Error())
		return
	}
	a.db.AddAudit(a.currentActor(r), "container.create", in.Name, in.Image)
	writeJSONStatus(w, 201, map[string]any{"id": id})
}
func (a *App) containerDelete(w http.ResponseWriter, r *http.Request) {
	d, err := a.docker()
	if err != nil {
		errorJSON(w, 503, "docker_unavailable", err.Error())
		return
	}
	in, err := decodeOptionalDeleteRequest(r)
	if err != nil {
		errorJSON(w, 400, "invalid_delete_options", err.Error())
		return
	}
	force := r.URL.Query().Get("force") == "true"
	if len(in.Volumes) == 0 && !in.RemoveImage && len(in.Networks) == 0 {
		name := ""
		if raw, inspectErr := d.ContainerInspect(r.Context(), r.PathValue("id")); inspectErr == nil {
			var meta struct {
				Name string `json:"Name"`
			}
			if json.Unmarshal(raw, &meta) == nil {
				name = strings.TrimPrefix(meta.Name, "/")
			}
		}
		if err := d.ContainerRemove(r.Context(), r.PathValue("id"), force); err != nil {
			errorJSON(w, 502, "delete_failed", err.Error())
			return
		}
		if name != "" {
			_ = a.db.DeletePendingContainerEdit(name)
		}
		a.db.AddAudit(a.currentActor(r), "container.delete", r.PathValue("id"), name)
		writeJSON(w, map[string]any{"ok": true, "deleted": map[string][]string{"volumes": {}, "networks": {}, "images": {}}, "warnings": []string{}})
		return
	}
	// Rebuild the plan immediately before removal. This is the server-side
	// safety check; Docker itself remains the final race-condition guard.
	plan, err := a.buildContainerDeletePlan(r.Context(), r.PathValue("id"))
	if err != nil {
		errorJSON(w, 502, "delete_plan_failed", err.Error())
		return
	}
	selected, err := selectedDeleteResources(plan, in)
	if err != nil {
		errorJSON(w, 409, "resource_in_use", err.Error())
		return
	}
	if err := d.ContainerRemove(r.Context(), plan.ContainerID, force); err != nil {
		errorJSON(w, 502, "delete_failed", err.Error())
		return
	}
	if plan.Name != "" {
		_ = a.db.DeletePendingContainerEdit(plan.Name)
	}
	deleted := map[string][]string{"volumes": {}, "networks": {}, "images": {}}
	warnings := []string{}
	for _, res := range selected {
		var removeErr error
		switch res.Kind {
		case "volume":
			removeErr = d.VolumeRemove(r.Context(), res.Name, false)
			if removeErr == nil {
				deleted["volumes"] = append(deleted["volumes"], res.Name)
				a.db.AddAudit(a.currentActor(r), "volume.delete", res.Name, "with container "+plan.Name)
			}
		case "network":
			removeErr = d.NetworkRemove(r.Context(), res.ID)
			if removeErr == nil {
				deleted["networks"] = append(deleted["networks"], res.Name)
				a.db.AddAudit(a.currentActor(r), "network.delete", res.ID, "with container "+plan.Name)
			}
		case "image":
			removeErr = d.ImageRemove(r.Context(), res.ID, true)
			if removeErr == nil {
				deleted["images"] = append(deleted["images"], res.Name)
				a.db.AddAudit(a.currentActor(r), "image.delete", res.ID, "with container "+plan.Name)
			}
		}
		if removeErr != nil {
			warnings = append(warnings, fmt.Sprintf("%s %s konnte nicht entfernt werden: %v", res.Kind, res.Name, removeErr))
		}
	}
	a.db.AddAudit(a.currentActor(r), "container.delete", plan.ContainerID, plan.Name)
	writeJSON(w, map[string]any{"ok": true, "deleted": deleted, "warnings": warnings})
}
func (a *App) containerAction(w http.ResponseWriter, r *http.Request) {
	action := r.PathValue("action")
	switch action {
	case "start", "stop", "restart", "pause", "unpause", "kill":
		if action == "start" || action == "restart" {
			if newID, name, applied, failure := a.applyPendingContainerEdit(r.Context(), r.PathValue("id"), true); failure != nil {
				errorJSON(w, failure.Status, failure.Code, failure.Msg)
				return
			} else if applied {
				a.db.AddAudit(a.currentActor(r), "container.edit.apply_pending", name, action)
				writeJSON(w, map[string]any{"ok": true, "container_id": newID, "pending_applied": true})
				return
			}
		}
		if action == "start" {
			if conflicts, err := a.existingContainerPortConflicts(r.Context(), r.PathValue("id")); err == nil && len(conflicts) > 0 {
				c := conflicts[0]
				msg := fmt.Sprintf("Port %s/%s wird bereits von %s verwendet", c.HostPort, c.Protocol, c.Container)
				if c.Suggestion != "" {
					msg += ". Freier Vorschlag: " + c.Suggestion
				}
				errorJSON(w, http.StatusConflict, "port_conflict", msg)
				return
			}
		}
		d, err := a.docker()
		if err != nil {
			errorJSON(w, 503, "docker_unavailable", err.Error())
			return
		}
		if err := d.ContainerAction(r.Context(), r.PathValue("id"), action); err != nil {
			errorJSON(w, 502, "docker_error", err.Error())
			return
		}
		a.db.AddAudit(a.currentActor(r), "container."+action, r.PathValue("id"), "")
		writeJSON(w, map[string]any{"ok": true})
	case "update-check":
		a.containerUpdateCheck(w, r)
	case "update":
		a.containerUpdate(w, r)
	case "rollback":
		a.containerRollback(w, r)
	default:
		errorJSON(w, 404, "unknown_action", "Unknown container action")
	}
}
func (a *App) containerLogs(w http.ResponseWriter, r *http.Request) {
	tail, _ := strconv.Atoi(r.URL.Query().Get("tail"))
	d, err := a.docker()
	if err != nil {
		errorJSON(w, 503, "docker_unavailable", err.Error())
		return
	}
	b, err := d.ContainerLogs(r.Context(), r.PathValue("id"), tail)
	if err != nil {
		errorJSON(w, 502, "docker_error", err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(b)
}
func (a *App) containerStats(w http.ResponseWriter, r *http.Request) {
	d, err := a.docker()
	if err != nil {
		errorJSON(w, 503, "docker_unavailable", err.Error())
		return
	}
	v, err := d.ContainerStats(r.Context(), r.PathValue("id"))
	if err != nil {
		errorJSON(w, 502, "docker_error", err.Error())
		return
	}
	writeRawJSON(w, v)
}

func (a *App) containerUpdateCheck(w http.ResponseWriter, r *http.Request) {
	v, err := a.checkContainerUpdate(r.Context(), r.PathValue("id"))
	if err != nil {
		if v.ImageRef != "" {
			writeJSON(w, map[string]any{"image": v.ImageRef, "status": v.Status, "current_digest": v.CurrentDigest, "remote_digest": v.RemoteDigest, "error": err.Error()})
			return
		}
		errorJSON(w, 502, "update_check_failed", err.Error())
		return
	}
	writeJSON(w, map[string]any{"image": v.ImageRef, "status": v.Status, "current_digest": v.CurrentDigest, "remote_digest": v.RemoteDigest, "checked_at": v.CheckedAt})
}
func (a *App) containerUpdate(w http.ResponseWriter, r *http.Request) {
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
	if err := json.Unmarshal(raw, &ci); err != nil {
		errorJSON(w, 500, "decode_error", err.Error())
		return
	}
	name := strings.TrimPrefix(asString(ci["Name"]), "/")
	configMap, _ := ci["Config"].(map[string]any)
	if labels, ok := configMap["Labels"].(map[string]any); ok {
		labelStrings := map[string]string{}
		for k, v := range labels {
			labelStrings[k] = asString(v)
		}
		if project := strings.TrimSpace(asString(labels["com.docker.compose.project"])); project != "" && !zentContainerStandaloneLabels(labelStrings) {
			errorJSON(w, 409, "compose_managed", "This container is managed by Compose project "+project+". Update the project instead.")
			return
		}
	}
	hostConfig, _ := ci["HostConfig"].(map[string]any)
	state, _ := ci["State"].(map[string]any)
	running, _ := state["Running"].(bool)
	imageRef := asString(configMap["Image"])
	oldNetworks := map[string]any{}
	if ns, ok := ci["NetworkSettings"].(map[string]any); ok {
		if nets, ok := ns["Networks"].(map[string]any); ok {
			oldNetworks = nets
		}
	}
	for netName, rawEP := range oldNetworks {
		if ep, ok := rawEP.(map[string]any); ok {
			if ipam, ok := ep["IPAMConfig"].(map[string]any); ok {
				if asString(ipam["IPv4Address"]) != "" || asString(ipam["IPv6Address"]) != "" {
					errorJSON(w, 409, "static_network_ip_update_blocked", "This container uses a static network IP on "+netName+". ZentContainer refuses the automatic update rather than risk changing network identity.")
					return
				}
			}
		}
	}
	if imageRef == "" {
		errorJSON(w, 400, "no_image", "Container has no image reference")
		return
	}
	if _, err := d.ImagePullAuth(r.Context(), imageRef, a.registryAuthForImage(imageRef)); err != nil {
		errorJSON(w, 502, "pull_failed", err.Error())
		return
	}
	if running {
		_ = d.ContainerAction(r.Context(), id, "stop")
	}
	backup := "zc-backup-" + safeName(name) + "-" + strconv.FormatInt(time.Now().Unix(), 10)
	if err := d.ContainerRename(r.Context(), id, backup); err != nil {
		if running {
			_ = d.ContainerAction(r.Context(), id, "start")
		}
		errorJSON(w, 502, "backup_failed", err.Error())
		return
	}
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
	newID, err := d.ContainerCreateMap(r.Context(), name, body)
	if err != nil {
		_ = d.ContainerRename(r.Context(), id, name)
		if running {
			_ = d.ContainerAction(r.Context(), id, "start")
		}
		errorJSON(w, 502, "recreate_failed", err.Error())
		return
	}
	if err := d.ContainerAction(r.Context(), newID, "start"); err != nil {
		_ = d.ContainerRemove(r.Context(), newID, true)
		_ = d.ContainerRename(r.Context(), id, name)
		if running {
			_ = d.ContainerAction(r.Context(), id, "start")
		}
		errorJSON(w, 502, "start_failed", "New container failed; old container restored: "+err.Error())
		return
	}
	newRaw, _ := d.ContainerInspect(r.Context(), newID)
	newNetworks := map[string]bool{}
	var ni map[string]any
	if json.Unmarshal(newRaw, &ni) == nil {
		if ns, ok := ni["NetworkSettings"].(map[string]any); ok {
			if nets, ok := ns["Networks"].(map[string]any); ok {
				for n := range nets {
					newNetworks[n] = true
				}
			}
		}
	}
	for netName, rawEP := range oldNetworks {
		if newNetworks[netName] || netName == "host" || netName == "none" {
			continue
		}
		epOut := map[string]any{}
		if ep, ok := rawEP.(map[string]any); ok {
			for _, key := range []string{"Aliases", "Links", "DriverOpts", "GwPriority"} {
				if v, exists := ep[key]; exists && v != nil {
					epOut[key] = v
				}
			}
		}
		if err := d.NetworkConnectConfig(r.Context(), netName, newID, epOut); err != nil {
			_ = d.ContainerRemove(r.Context(), newID, true)
			_ = d.ContainerRename(r.Context(), id, name)
			if running {
				_ = d.ContainerAction(r.Context(), id, "start")
			}
			errorJSON(w, 502, "network_restore_failed", "Replacement could not be attached to network "+netName+"; old container restored: "+err.Error())
			return
		}
	}
	healthTimeout := time.Duration(a.getRuntimeSettings().HealthTimeoutSeconds) * time.Second
	if err := waitContainerHealthy(r.Context(), d, newID, healthTimeout); err != nil {
		_ = d.ContainerRemove(context.Background(), newID, true)
		_ = d.ContainerRename(context.Background(), id, name)
		if running {
			_ = d.ContainerAction(context.Background(), id, "start")
		}
		errorJSON(w, 502, "healthcheck_failed", "New container failed health verification; previous container restored: "+err.Error())
		return
	}
	a.db.AddAudit(a.currentActor(r), "container.update", name, "backup="+backup)
	writeJSON(w, map[string]any{"ok": true, "container_id": newID, "rollback_available": true, "backup": backup})
}
func (a *App) containerRollback(w http.ResponseWriter, r *http.Request) {
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
	var cur struct {
		Name  string `json:"Name"`
		Image string `json:"Image"`
	}
	_ = json.Unmarshal(raw, &cur)
	name := strings.TrimPrefix(cur.Name, "/")
	all, err := d.Containers(r.Context(), true)
	if err != nil {
		errorJSON(w, 502, "docker_error", err.Error())
		return
	}
	prefixes := []string{"/zc-backup-" + safeName(name) + "-", "/.zc-backup-" + safeName(name) + "-"}
	var backups []dockerx.ContainerSummary
	for _, c := range all {
		for _, n := range c.Names {
			for _, prefix := range prefixes {
				if strings.HasPrefix(n, prefix) {
					backups = append(backups, c)
					break
				}
			}
		}
	}
	if len(backups) == 0 {
		errorJSON(w, 404, "no_rollback", "No rollback container is available")
		return
	}
	sort.Slice(backups, func(i, j int) bool { return backups[i].Created > backups[j].Created })
	old := backups[0]
	_ = d.ContainerAction(r.Context(), id, "stop")
	temp := "zc-failed-" + safeName(name) + "-" + strconv.FormatInt(time.Now().Unix(), 10)
	if err := d.ContainerRename(r.Context(), id, temp); err != nil {
		errorJSON(w, 502, "rollback_failed", err.Error())
		return
	}
	if err := d.ContainerRename(r.Context(), old.ID, name); err != nil {
		_ = d.ContainerRename(r.Context(), id, name)
		errorJSON(w, 502, "rollback_failed", err.Error())
		return
	}
	if err := d.ContainerAction(r.Context(), old.ID, "start"); err != nil {
		errorJSON(w, 502, "rollback_failed", err.Error())
		return
	}
	_ = d.ContainerRemove(r.Context(), id, true)
	if cur.Image != "" {
		remaining, _ := d.Containers(r.Context(), true)
		used := false
		for _, c := range remaining {
			if c.ImageID == cur.Image {
				used = true
				break
			}
		}
		if !used {
			_ = d.ImageRemove(r.Context(), cur.Image, false)
		}
	}
	a.db.AddAudit(a.currentActor(r), "container.rollback", name, "")
	writeJSON(w, map[string]any{"ok": true, "container_id": old.ID})
}

func (a *App) containerTerminal(w http.ResponseWriter, r *http.Request) {
	d, err := a.docker()
	if err != nil {
		errorJSON(w, 503, "docker_unavailable", err.Error())
		return
	}
	shell := r.URL.Query().Get("shell")
	if shell == "" {
		shell = "/bin/sh"
	}
	execID, err := d.ExecCreate(r.Context(), r.PathValue("id"), []string{shell})
	if err != nil {
		errorJSON(w, 502, "exec_failed", err.Error())
		return
	}
	ws, err := acceptWS(w, r)
	if err != nil {
		return
	}
	defer ws.Close()
	dc, err := d.ExecAttach(r.Context(), execID)
	if err != nil {
		_ = ws.WriteFrame(1, []byte("Unable to open Docker exec: "+err.Error()))
		return
	}
	defer dc.Close()
	a.db.AddAudit(a.currentActor(r), "terminal.open", r.PathValue("id"), shell)
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 8192)
		for {
			n, err := dc.Read(buf)
			if n > 0 {
				if ws.WriteFrame(2, buf[:n]) != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		close(done)
	}()
	for {
		select {
		case <-done:
			return
		default:
		}
		op, p, err := ws.ReadFrame()
		if err != nil {
			return
		}
		if op == 8 {
			return
		}
		if op == 9 {
			_ = ws.WriteFrame(10, p)
			continue
		}
		if op == 1 && bytes.HasPrefix(p, []byte(`{"type":"resize"`)) {
			var x struct {
				Type       string `json:"type"`
				Cols, Rows int
			}
			if json.Unmarshal(p, &x) == nil && x.Cols > 0 && x.Rows > 0 {
				_ = d.ExecResize(context.Background(), execID, x.Rows, x.Cols)
			}
			continue
		}
		if op == 1 || op == 2 {
			_, _ = dc.Write(p)
		}
	}
}

func (a *App) images(w http.ResponseWriter, r *http.Request) {
	d, err := a.docker()
	if err != nil {
		errorJSON(w, 503, "docker_unavailable", err.Error())
		return
	}
	v, err := d.Images(r.Context())
	if err != nil {
		errorJSON(w, 502, "docker_error", err.Error())
		return
	}
	containers, _ := d.Containers(r.Context(), true)
	usage := map[string][]string{}
	for _, c := range containers {
		for _, img := range v {
			if c.ImageID == img.ID {
				n := c.ID[:min(12, len(c.ID))]
				if len(c.Names) > 0 {
					n = strings.TrimPrefix(c.Names[0], "/")
				}
				usage[img.ID] = append(usage[img.ID], n)
			}
		}
	}
	writeJSON(w, map[string]any{"images": v, "usage": usage})
}
func (a *App) imagePull(w http.ResponseWriter, r *http.Request) {
	var in struct{ Image string }
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.Image == "" {
		errorJSON(w, 400, "invalid_image", "image is required")
		return
	}
	d, err := a.docker()
	if err != nil {
		errorJSON(w, 503, "docker_unavailable", err.Error())
		return
	}
	out, err := d.ImagePullAuth(r.Context(), in.Image, a.registryAuthForImage(in.Image))
	if err != nil {
		errorJSON(w, 502, "pull_failed", err.Error())
		return
	}
	a.db.AddAudit(a.currentActor(r), "image.pull", in.Image, "")
	writeJSON(w, map[string]any{"ok": true, "output": string(out)})
}
func (a *App) imageInspect(w http.ResponseWriter, r *http.Request) {
	d, err := a.docker()
	if err != nil {
		errorJSON(w, 503, "docker_unavailable", err.Error())
		return
	}
	v, err := d.ImageInspect(r.Context(), r.PathValue("id"))
	if err != nil {
		errorJSON(w, 502, "docker_error", err.Error())
		return
	}
	writeRawJSON(w, v)
}
func (a *App) imageDelete(w http.ResponseWriter, r *http.Request) {
	d, err := a.docker()
	if err != nil {
		errorJSON(w, 503, "docker_unavailable", err.Error())
		return
	}
	if err := d.ImageRemove(r.Context(), r.PathValue("id"), false); err != nil {
		errorJSON(w, 409, "image_in_use", err.Error())
		return
	}
	a.db.AddAudit(a.currentActor(r), "image.delete", r.PathValue("id"), "")
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) volumes(w http.ResponseWriter, r *http.Request) {
	d, err := a.docker()
	if err != nil {
		errorJSON(w, 503, "docker_unavailable", err.Error())
		return
	}
	v, err := d.Volumes(r.Context())
	if err != nil {
		errorJSON(w, 502, "docker_error", err.Error())
		return
	}
	containers, _ := d.Containers(r.Context(), true)
	usage := map[string][]string{}
	for _, c := range containers {
		for _, m := range c.Mounts {
			if m.Type == "volume" {
				n := c.ID[:min(12, len(c.ID))]
				if len(c.Names) > 0 {
					n = strings.TrimPrefix(c.Names[0], "/")
				}
				usage[m.Name] = append(usage[m.Name], n)
			}
		}
	}
	sizes, _ := d.VolumeDiskUsage(r.Context())
	writeJSON(w, map[string]any{"volumes": v, "usage": usage, "sizes": sizes})
}
func (a *App) volumeInspect(w http.ResponseWriter, r *http.Request) {
	d, err := a.docker()
	if err != nil {
		errorJSON(w, 503, "docker_unavailable", err.Error())
		return
	}
	v, err := d.VolumeInspect(r.Context(), r.PathValue("name"))
	if err != nil {
		errorJSON(w, 502, "docker_error", err.Error())
		return
	}
	writeRawJSON(w, v)
}
func (a *App) volumeSize(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if d, err := a.docker(); err == nil {
		if sizes, err := d.VolumeDiskUsage(r.Context()); err == nil {
			if size, ok := sizes[name]; ok {
				writeJSON(w, map[string]any{"bytes": size, "source": "docker"})
				return
			}
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	out, err := a.helperRun(ctx, name, false, "fs", "size", "/")
	if err != nil {
		errorJSON(w, 502, "volume_size_failed", err.Error())
		return
	}
	var data map[string]any
	if err := json.Unmarshal(out, &data); err != nil {
		errorJSON(w, 500, "helper_error", strings.TrimSpace(string(out)))
		return
	}
	data["source"] = "helper"
	writeJSON(w, data)
}

func (a *App) volumeCreate(w http.ResponseWriter, r *http.Request) {
	var in struct{ Name, Driver string }
	if !decodeJSON(w, r, &in) {
		return
	}
	d, err := a.docker()
	if err != nil {
		errorJSON(w, 503, "docker_unavailable", err.Error())
		return
	}
	v, err := d.VolumeCreate(r.Context(), in.Name, in.Driver)
	if err != nil {
		errorJSON(w, 502, "create_failed", err.Error())
		return
	}
	a.db.AddAudit(a.currentActor(r), "volume.create", v.Name, "")
	writeJSONStatus(w, 201, v)
}
func (a *App) volumeDelete(w http.ResponseWriter, r *http.Request) {
	d, err := a.docker()
	if err != nil {
		errorJSON(w, 503, "docker_unavailable", err.Error())
		return
	}
	if err := d.VolumeRemove(r.Context(), r.PathValue("name"), false); err != nil {
		errorJSON(w, 409, "volume_in_use", err.Error())
		return
	}
	a.db.AddAudit(a.currentActor(r), "volume.delete", r.PathValue("name"), "")
	writeJSON(w, map[string]any{"ok": true})
}
func (a *App) volumeFiles(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Query().Get("path")
	if p == "" {
		p = "/"
	}
	out, err := a.helperRun(r.Context(), r.PathValue("name"), false, "fs", "list", p)
	if err != nil {
		errorJSON(w, 502, "volume_browse_failed", err.Error())
		return
	}
	var data any
	if json.Unmarshal(out, &data) != nil {
		errorJSON(w, 500, "helper_error", string(out))
		return
	}
	writeJSON(w, data)
}
func (a *App) volumeMkdir(w http.ResponseWriter, r *http.Request) {
	var in struct{ Path string }
	if !decodeJSON(w, r, &in) {
		return
	}
	_, err := a.helperRun(r.Context(), r.PathValue("name"), true, "fs", "mkdir", in.Path)
	if err != nil {
		errorJSON(w, 502, "mkdir_failed", err.Error())
		return
	}
	a.db.AddAudit(a.currentActor(r), "volume.mkdir", r.PathValue("name"), in.Path)
	writeJSON(w, map[string]any{"ok": true})
}
func (a *App) volumeFileDelete(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Query().Get("path")
	if p == "" || p == "/" {
		errorJSON(w, 400, "invalid_path", "Refusing to delete volume root")
		return
	}
	_, err := a.helperRun(r.Context(), r.PathValue("name"), true, "fs", "delete", p)
	if err != nil {
		errorJSON(w, 502, "delete_failed", err.Error())
		return
	}
	a.db.AddAudit(a.currentActor(r), "volume.file.delete", r.PathValue("name"), p)
	writeJSON(w, map[string]any{"ok": true})
}
func (a *App) volumeDownload(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Query().Get("path")
	if p == "" {
		errorJSON(w, 400, "invalid_path", "path is required")
		return
	}
	data, name, err := a.helperArchiveRead(r.Context(), r.PathValue("name"), p)
	if err != nil {
		errorJSON(w, 502, "read_failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	w.Write(data)
}
func (a *App) volumeWrite(w http.ResponseWriter, r *http.Request) {
	var in struct{ Path, Content string }
	if !decodeJSON(w, r, &in) {
		return
	}
	if len(in.Content) > 5*1024*1024 {
		errorJSON(w, 413, "file_too_large", "Editor writes are limited to 5 MB")
		return
	}
	if err := a.helperArchiveWrite(r.Context(), r.PathValue("name"), in.Path, []byte(in.Content)); err != nil {
		errorJSON(w, 502, "write_failed", err.Error())
		return
	}
	a.db.AddAudit(a.currentActor(r), "volume.file.write", r.PathValue("name"), in.Path)
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) volumeUpload(w http.ResponseWriter, r *http.Request) {
	const maxFile = int64(100 << 20)
	// Leave a small allowance for multipart headers but strictly reject oversized requests/files.
	r.Body = http.MaxBytesReader(w, r.Body, maxFile+(1<<20))
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "request body too large") {
			errorJSON(w, 413, "file_too_large", "Uploads are limited to 100 MB")
			return
		}
		errorJSON(w, 400, "invalid_upload", err.Error())
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	f, h, err := r.FormFile("file")
	if err != nil {
		errorJSON(w, 400, "missing_file", "file is required")
		return
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	if err != nil {
		errorJSON(w, 400, "upload_failed", err.Error())
		return
	}
	if int64(len(data)) > maxFile {
		errorJSON(w, 413, "file_too_large", "Uploads are limited to 100 MB")
		return
	}
	base := strings.TrimSpace(r.FormValue("path"))
	if base == "" {
		base = "/"
	}
	base, err = cleanVolumePath(base)
	if err != nil {
		errorJSON(w, 400, "invalid_path", err.Error())
		return
	}
	name := filepath.Base(h.Filename)
	if name == "." || name == "/" || name == "" {
		errorJSON(w, 400, "invalid_filename", "invalid filename")
		return
	}
	target := filepath.ToSlash(filepath.Join(base, name))
	if err := a.helperArchiveWrite(r.Context(), r.PathValue("name"), target, data); err != nil {
		errorJSON(w, 502, "upload_failed", err.Error())
		return
	}
	a.db.AddAudit(a.currentActor(r), "volume.file.upload", r.PathValue("name"), target)
	writeJSONStatus(w, 201, map[string]any{"ok": true, "path": target})
}

func (a *App) volumeArchive(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Query().Get("path")
	if p == "" {
		p = "/"
	}
	data, name, err := a.helperArchiveDownload(r.Context(), r.PathValue("name"), p)
	if err != nil {
		errorJSON(w, 502, "archive_failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	w.Write(data)
}

func (a *App) networks(w http.ResponseWriter, r *http.Request) {
	d, err := a.docker()
	if err != nil {
		errorJSON(w, 503, "docker_unavailable", err.Error())
		return
	}
	v, err := d.Networks(r.Context())
	if err != nil {
		errorJSON(w, 502, "docker_error", err.Error())
		return
	}
	writeJSON(w, v)
}
func (a *App) networkInspect(w http.ResponseWriter, r *http.Request) {
	d, err := a.docker()
	if err != nil {
		errorJSON(w, 503, "docker_unavailable", err.Error())
		return
	}
	v, err := d.NetworkInspect(r.Context(), r.PathValue("id"))
	if err != nil {
		errorJSON(w, 502, "docker_error", err.Error())
		return
	}
	writeRawJSON(w, v)
}
func (a *App) networkCreate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name, Driver, Subnet, Gateway, Parent string
		EnableIPv6, Internal, Attachable      bool
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.Driver == "" {
		in.Driver = "bridge"
	}
	d, err := a.docker()
	if err != nil {
		errorJSON(w, 503, "docker_unavailable", err.Error())
		return
	}
	id, err := d.NetworkCreateAdvanced(r.Context(), dockerx.NetworkCreateRequest{Name: in.Name, Driver: in.Driver, Subnet: in.Subnet, Gateway: in.Gateway, Parent: in.Parent, EnableIPv6: in.EnableIPv6, Internal: in.Internal, Attachable: in.Attachable})
	if err != nil {
		errorJSON(w, 502, "create_failed", err.Error())
		return
	}
	a.db.AddAudit(a.currentActor(r), "network.create", in.Name, in.Driver)
	writeJSONStatus(w, 201, map[string]any{"id": id})
}
func (a *App) networkDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	d, err := a.docker()
	if err != nil {
		errorJSON(w, 503, "docker_unavailable", err.Error())
		return
	}
	if raw, e := d.NetworkInspect(r.Context(), id); e == nil {
		var meta struct {
			Name string `json:"Name"`
		}
		_ = json.Unmarshal(raw, &meta)
		if meta.Name == "bridge" || meta.Name == "host" || meta.Name == "none" {
			errorJSON(w, 400, "protected_network", "Built-in networks cannot be removed")
			return
		}
	}
	if err := d.NetworkRemove(r.Context(), id); err != nil {
		errorJSON(w, 409, "delete_failed", err.Error())
		return
	}
	a.db.AddAudit(a.currentActor(r), "network.delete", id, "")
	writeJSON(w, map[string]any{"ok": true})
}
func (a *App) networkConnect(w http.ResponseWriter, r *http.Request) {
	var in struct{ Container string }
	if !decodeJSON(w, r, &in) {
		return
	}
	d, err := a.docker()
	if err != nil {
		errorJSON(w, 503, "docker_unavailable", err.Error())
		return
	}
	if err := d.NetworkConnect(r.Context(), r.PathValue("id"), in.Container); err != nil {
		errorJSON(w, 502, "connect_failed", err.Error())
		return
	}
	a.db.AddAudit(a.currentActor(r), "network.connect", r.PathValue("id"), in.Container)
	writeJSON(w, map[string]any{"ok": true})
}
func (a *App) networkDisconnect(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Container string
		Force     bool
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	d, err := a.docker()
	if err != nil {
		errorJSON(w, 503, "docker_unavailable", err.Error())
		return
	}
	if err := d.NetworkDisconnect(r.Context(), r.PathValue("id"), in.Container, in.Force); err != nil {
		errorJSON(w, 502, "disconnect_failed", err.Error())
		return
	}
	a.db.AddAudit(a.currentActor(r), "network.disconnect", r.PathValue("id"), in.Container)
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) projectList(w http.ResponseWriter, r *http.Request) {
	v, err := a.projects.List()
	if err != nil {
		errorJSON(w, 500, "project_error", err.Error())
		return
	}
	writeJSON(w, v)
}
func (a *App) projectGet(w http.ResponseWriter, r *http.Request) {
	v, err := a.projects.Get(r.PathValue("name"))
	if err != nil {
		errorJSON(w, 404, "project_not_found", err.Error())
		return
	}
	writeJSON(w, v)
}
func (a *App) projectSave(w http.ResponseWriter, r *http.Request) {
	var in struct{ Name, Compose, Env string }
	if !decodeJSON(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.Name) == "" {
		errorJSON(w, 400, "project_save_failed", "project name is required")
		return
	}
	var err error
	if strings.TrimSpace(in.Compose) == "" {
		err = a.projects.Create(in.Name)
	} else {
		err = a.projects.Save(in.Name, in.Compose, in.Env)
	}
	if err != nil {
		errorJSON(w, 400, "project_save_failed", err.Error())
		return
	}
	a.db.AddAudit(a.currentActor(r), "project.create", in.Name, "")
	writeJSONStatus(w, 201, map[string]any{"ok": true, "name": in.Name})
}
func (a *App) projectValidateContent(w http.ResponseWriter, r *http.Request) {
	var in struct{ Name, Compose, Env string }
	if !decodeJSON(w, r, &in) {
		return
	}
	out, err := a.projects.ValidateContent(in.Name, in.Compose, in.Env)
	if err != nil {
		errorJSON(w, 400, "compose_invalid", err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true, "output": out})
}
func (a *App) projectSaveNamed(w http.ResponseWriter, r *http.Request) {
	var in struct{ Compose, Env string }
	if !decodeJSON(w, r, &in) {
		return
	}
	name := r.PathValue("name")
	if err := a.projects.Save(name, in.Compose, in.Env); err != nil {
		errorJSON(w, 400, "project_save_failed", err.Error())
		return
	}
	a.db.AddAudit(a.currentActor(r), "project.save", name, "legacy compose editor")
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) projectFiles(w http.ResponseWriter, r *http.Request) {
	v, err := a.projects.ListFiles(r.PathValue("name"), r.URL.Query().Get("path"))
	if err != nil {
		errorJSON(w, 400, "project_files_failed", err.Error())
		return
	}
	writeJSON(w, v)
}
func (a *App) projectFileGet(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	b, st, err := a.projects.ReadFile(r.PathValue("name"), path)
	if err != nil {
		errorJSON(w, 404, "project_file_not_found", err.Error())
		return
	}
	if len(b) > 5*1024*1024 {
		errorJSON(w, 413, "file_too_large", "Files larger than 5 MB are download-only")
		return
	}
	if bytes.IndexByte(b, 0) >= 0 {
		errorJSON(w, 415, "binary_file", "Binary files are download-only")
		return
	}
	writeJSON(w, map[string]any{"path": path, "content": string(b), "size": st.Size(), "modified": st.ModTime().Unix()})
}
func (a *App) projectFilePut(w http.ResponseWriter, r *http.Request) {
	var in struct{ Path, Content string }
	if !decodeJSON(w, r, &in) {
		return
	}
	if len(in.Content) > 5*1024*1024 {
		errorJSON(w, 413, "file_too_large", "Editor writes are limited to 5 MB")
		return
	}
	if err := a.projects.WriteFile(r.PathValue("name"), in.Path, []byte(in.Content)); err != nil {
		errorJSON(w, 400, "project_file_write_failed", err.Error())
		return
	}
	a.db.AddAudit(a.currentActor(r), "project.file.write", r.PathValue("name"), in.Path)
	writeJSON(w, map[string]any{"ok": true})
}
func (a *App) projectFileDelete(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if err := a.projects.RemoveFile(r.PathValue("name"), path); err != nil {
		errorJSON(w, 400, "project_file_delete_failed", err.Error())
		return
	}
	a.db.AddAudit(a.currentActor(r), "project.file.delete", r.PathValue("name"), path)
	writeJSON(w, map[string]any{"ok": true})
}
func (a *App) projectMkdir(w http.ResponseWriter, r *http.Request) {
	var in struct{ Path string }
	if !decodeJSON(w, r, &in) {
		return
	}
	if err := a.projects.Mkdir(r.PathValue("name"), in.Path); err != nil {
		errorJSON(w, 400, "project_mkdir_failed", err.Error())
		return
	}
	a.db.AddAudit(a.currentActor(r), "project.directory.create", r.PathValue("name"), in.Path)
	writeJSONStatus(w, 201, map[string]any{"ok": true})
}
func (a *App) projectRename(w http.ResponseWriter, r *http.Request) {
	var in struct{ From, To string }
	if !decodeJSON(w, r, &in) {
		return
	}
	if err := a.projects.Rename(r.PathValue("name"), in.From, in.To); err != nil {
		errorJSON(w, 400, "project_rename_failed", err.Error())
		return
	}
	a.db.AddAudit(a.currentActor(r), "project.file.rename", r.PathValue("name"), in.From+" -> "+in.To)
	writeJSON(w, map[string]any{"ok": true})
}
func (a *App) projectUpload(w http.ResponseWriter, r *http.Request) {
	const maxFile = int64(100 << 20)
	r.Body = http.MaxBytesReader(w, r.Body, maxFile+(1<<20))
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		errorJSON(w, 400, "invalid_upload", err.Error())
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	f, h, err := r.FormFile("file")
	if err != nil {
		errorJSON(w, 400, "missing_file", "file is required")
		return
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	if err != nil {
		errorJSON(w, 400, "upload_failed", err.Error())
		return
	}
	if int64(len(data)) > maxFile {
		errorJSON(w, 413, "file_too_large", "Uploads are limited to 100 MB")
		return
	}
	base := strings.Trim(strings.ReplaceAll(r.FormValue("path"), "\\", "/"), "/")
	name := filepath.Base(h.Filename)
	if name == "." || name == "/" || name == "" {
		errorJSON(w, 400, "invalid_filename", "invalid filename")
		return
	}
	target := filepath.ToSlash(filepath.Join(base, name))
	if err := a.projects.WriteFile(r.PathValue("name"), target, data); err != nil {
		errorJSON(w, 400, "upload_failed", err.Error())
		return
	}
	a.db.AddAudit(a.currentActor(r), "project.file.upload", r.PathValue("name"), target)
	writeJSONStatus(w, 201, map[string]any{"ok": true, "path": target})
}
func (a *App) projectDownload(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	b, _, err := a.projects.ReadFile(r.PathValue("name"), path)
	if err != nil {
		errorJSON(w, 404, "project_file_not_found", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filepath.Base(path)))
	w.Write(b)
}
func (a *App) projectAnalysis(w http.ResponseWriter, r *http.Request) {
	v, err := a.projects.Analyze(r.PathValue("name"))
	if err != nil {
		errorJSON(w, 400, "project_analysis_failed", err.Error())
		return
	}
	writeJSON(w, v)
}
func (a *App) projectStatus(w http.ResponseWriter, r *http.Request) {
	v, err := a.projects.Status(r.PathValue("name"))
	if err != nil {
		errorJSON(w, 400, "project_status_failed", err.Error())
		return
	}
	writeJSON(w, v)
}
func (a *App) projectComposeFile(w http.ResponseWriter, r *http.Request) {
	var in struct{ Path string }
	if !decodeJSON(w, r, &in) {
		return
	}
	if err := a.projects.SetComposeFile(r.PathValue("name"), in.Path); err != nil {
		errorJSON(w, 400, "compose_file_failed", err.Error())
		return
	}
	a.db.AddAudit(a.currentActor(r), "project.compose.select", r.PathValue("name"), in.Path)
	writeJSON(w, map[string]any{"ok": true})
}
func (a *App) projectFileRevisions(w http.ResponseWriter, r *http.Request) {
	v, err := a.projects.ListFileRevisions(r.PathValue("name"))
	if err != nil {
		errorJSON(w, 400, "project_history_failed", err.Error())
		return
	}
	writeJSON(w, v)
}
func (a *App) projectFileRevisionGet(w http.ResponseWriter, r *http.Request) {
	v, err := a.projects.GetFileRevision(r.PathValue("name"), r.PathValue("revision"))
	if err != nil {
		errorJSON(w, 404, "revision_not_found", err.Error())
		return
	}
	writeJSON(w, v)
}
func (a *App) projectFileRevisionRestore(w http.ResponseWriter, r *http.Request) {
	if err := a.projects.RestoreFileRevision(r.PathValue("name"), r.PathValue("revision")); err != nil {
		errorJSON(w, 400, "revision_restore_failed", err.Error())
		return
	}
	a.db.AddAudit(a.currentActor(r), "project.file.restore", r.PathValue("name"), r.PathValue("revision"))
	writeJSON(w, map[string]any{"ok": true})
}
func (a *App) projectDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if p, err := a.projects.Get(name); err == nil && p.HasCompose {
		if _, err := a.projects.Down(name); err != nil && !strings.Contains(strings.ToLower(err.Error()), "no such") && !strings.Contains(strings.ToLower(err.Error()), "not found") {
			errorJSON(w, 409, "project_down_failed", err.Error())
			return
		}
	}
	if err := a.projects.Delete(name); err != nil {
		errorJSON(w, 500, "project_delete_failed", err.Error())
		return
	}
	a.db.AddAudit(a.currentActor(r), "project.delete", name, "")
	writeJSON(w, map[string]any{"ok": true})
}
func (a *App) projectAction(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	action := r.PathValue("action")
	var out string
	var err error
	switch action {
	case "validate":
		out, err = a.projects.Validate(name)
	case "config":
		out, err = a.projects.Config(name)
	case "deploy":
		var in struct {
			Profiles []string `json:"profiles"`
		}
		_ = decodeJSONOptional(r, &in)
		if len(in.Profiles) > 0 {
			out, err = a.projects.DeployProfiles(name, in.Profiles)
		} else {
			out, err = a.projects.Deploy(name)
		}
	case "down":
		out, err = a.projects.Down(name)
	case "stop":
		out, err = a.projects.Stop(name)
	case "start":
		out, err = a.projects.Start(name)
	case "restart":
		out, err = a.projects.Restart(name)
	case "pull":
		out, err = a.projects.Pull(name)
	case "update":
		out, err = a.projects.Update(name)
	default:
		errorJSON(w, 404, "unknown_action", "Unknown project action")
		return
	}
	if err != nil {
		errorJSON(w, 400, "project_action_failed", err.Error())
		return
	}
	a.db.AddAudit(a.currentActor(r), "project."+action, name, "")
	writeJSON(w, map[string]any{"ok": true, "output": out})
}
func (a *App) projectLogs(w http.ResponseWriter, r *http.Request) {
	tail, _ := strconv.Atoi(r.URL.Query().Get("tail"))
	out, err := a.projects.Logs(r.PathValue("name"), tail)
	if err != nil {
		errorJSON(w, 400, "project_logs_failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(out))
}

func (a *App) apiKeys(w http.ResponseWriter, r *http.Request) {
	v, err := a.db.ListAPIKeys()
	if err != nil {
		errorJSON(w, 500, "db_error", err.Error())
		return
	}
	writeJSON(w, v)
}
func (a *App) apiKeyCreate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name   string
		Scopes []string
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.Name == "" {
		errorJSON(w, 400, "invalid_name", "name is required")
		return
	}
	prefix, _ := randomHex(4)
	secret, _ := auth.RandomToken(32)
	if len(in.Scopes) == 0 {
		in.Scopes = []string{"hosts.read", "containers.read", "images.read", "volumes.read", "networks.read", "projects.read"}
	}
	seen := map[string]bool{}
	cleanScopes := make([]string, 0, len(in.Scopes))
	for _, scope := range in.Scopes {
		scope = strings.TrimSpace(scope)
		if !validAPIScopes[scope] {
			errorJSON(w, 400, "invalid_scope", "Unknown API scope: "+scope)
			return
		}
		if !seen[scope] {
			seen[scope] = true
			cleanScopes = append(cleanScopes, scope)
		}
	}
	in.Scopes = cleanScopes
	_, err := a.db.CreateAPIKey(in.Name, prefix, auth.TokenHash(secret), strings.Join(in.Scopes, ","))
	if err != nil {
		errorJSON(w, 500, "db_error", err.Error())
		return
	}
	a.db.AddAudit(a.currentActor(r), "api_key.create", in.Name, "")
	writeJSONStatus(w, 201, map[string]any{"name": in.Name, "token": "zc_live_" + prefix + "_" + secret, "scopes": in.Scopes, "warning": "This token is shown only once."})
}
func (a *App) apiKeyDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		errorJSON(w, 400, "invalid_id", "invalid key id")
		return
	}
	if err := a.db.DeleteAPIKey(id); err != nil {
		errorJSON(w, 500, "db_error", err.Error())
		return
	}
	a.db.AddAudit(a.currentActor(r), "api_key.delete", r.PathValue("id"), "")
	writeJSON(w, map[string]any{"ok": true})
}
func (a *App) activity(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	v, err := a.db.AuditList(limit)
	if err != nil {
		errorJSON(w, 500, "db_error", err.Error())
		return
	}
	writeJSON(w, v)
}

func (a *App) helperImage(ctx context.Context) (string, error) {
	d, err := a.docker()
	if err != nil {
		return "", err
	}
	host, _ := os.Hostname()
	raw, err := d.ContainerInspect(ctx, host)
	if err != nil {
		return "", fmt.Errorf("cannot determine ZentContainer image; run ZentContainer as a Docker container: %w", err)
	}
	var v struct {
		Image string `json:"Image"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", err
	}
	if v.Image == "" {
		return "", errors.New("self image id unavailable")
	}
	return v.Image, nil
}
func (a *App) helperRun(ctx context.Context, volume string, rw bool, args ...string) ([]byte, error) {
	d, err := a.docker()
	if err != nil {
		return nil, err
	}
	img, err := a.helperImage(ctx)
	if err != nil {
		return nil, err
	}
	mode := ":ro"
	if rw {
		mode = ":rw"
	}
	id, err := d.ContainerCreate(ctx, "", dockerx.CreateContainerRequest{Image: img, Cmd: append([]string{"helper"}, args...), HostConfig: dockerx.HostConfig{Binds: []string{volume + ":/mnt/volume" + mode}, NetworkMode: "none"}})
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
	return d.ContainerOutput(ctx, id, 10000, false)
}

func (a *App) helperHold(ctx context.Context, volume string, rw bool) (*dockerx.Client, string, error) {
	d, err := a.docker()
	if err != nil {
		return nil, "", err
	}
	img, err := a.helperImage(ctx)
	if err != nil {
		return nil, "", err
	}
	mode := ":ro"
	if rw {
		mode = ":rw"
	}
	id, err := d.ContainerCreate(ctx, "", dockerx.CreateContainerRequest{Image: img, Cmd: []string{"helper", "hold"}, HostConfig: dockerx.HostConfig{Binds: []string{volume + ":/mnt/volume" + mode}, NetworkMode: "none"}})
	if err != nil {
		return nil, "", err
	}
	if err := d.ContainerAction(ctx, id, "start"); err != nil {
		_ = d.ContainerRemove(context.Background(), id, true)
		return nil, "", err
	}
	return d, id, nil
}
func cleanVolumePath(p string) (string, error) {
	p = filepath.ToSlash(filepath.Clean("/" + p))
	if p == "/.." || strings.HasPrefix(p, "/../") {
		return "", errors.New("invalid path")
	}
	return p, nil
}
func (a *App) helperArchiveRead(ctx context.Context, volume, p string) ([]byte, string, error) {
	p, err := cleanVolumePath(p)
	if err != nil {
		return nil, "", err
	}
	d, id, err := a.helperHold(ctx, volume, false)
	if err != nil {
		return nil, "", err
	}
	defer d.ContainerRemove(context.Background(), id, true)
	tarData, err := d.RawBytes(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/archive?path="+url.QueryEscape("/mnt/volume"+p), "", nil)
	if err != nil {
		return nil, "", err
	}
	tr := tar.NewReader(bytes.NewReader(tarData))
	h, err := tr.Next()
	if err != nil {
		return nil, "", err
	}
	if h.FileInfo().IsDir() {
		gz, name, err := gzipTar(tarData, filepath.Base(strings.TrimSuffix(p, "/")))
		return gz, name, err
	}
	b, err := io.ReadAll(io.LimitReader(tr, 50*1024*1024))
	return b, filepath.Base(p), err
}

func (a *App) helperArchiveDownload(ctx context.Context, volume, p string) ([]byte, string, error) {
	p, err := cleanVolumePath(p)
	if err != nil {
		return nil, "", err
	}
	d, id, err := a.helperHold(ctx, volume, false)
	if err != nil {
		return nil, "", err
	}
	defer d.ContainerRemove(context.Background(), id, true)
	tarData, err := d.RawBytes(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/archive?path="+url.QueryEscape("/mnt/volume"+p), "", nil)
	if err != nil {
		return nil, "", err
	}
	name := filepath.Base(strings.TrimSuffix(p, "/"))
	if p == "/" || name == "." || name == "" {
		name = safeName(volume)
	}
	return gzipTar(tarData, name)
}

func gzipTar(tarData []byte, name string) ([]byte, string, error) {
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	if _, err := zw.Write(tarData); err != nil {
		return nil, "", err
	}
	if err := zw.Close(); err != nil {
		return nil, "", err
	}
	if name == "" || name == "." {
		name = "volume"
	}
	return out.Bytes(), name + ".tar.gz", nil
}
func (a *App) helperArchiveWrite(ctx context.Context, volume, p string, data []byte) error {
	p, err := cleanVolumePath(p)
	if err != nil {
		return err
	}
	if p == "/" {
		return errors.New("file path required")
	}
	d, id, err := a.helperHold(ctx, volume, true)
	if err != nil {
		return err
	}
	defer d.ContainerRemove(context.Background(), id, true)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	name := filepath.Base(p)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(data)), ModTime: time.Now()}); err != nil {
		return err
	}
	if _, err := tw.Write(data); err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}
	parent := filepath.ToSlash(filepath.Dir("/mnt/volume" + p))
	_, err = d.RawBytes(ctx, http.MethodPut, "/containers/"+url.PathEscape(id)+"/archive?path="+url.QueryEscape(parent), "application/x-tar", bytes.NewReader(buf.Bytes()))
	return err
}

func (a *App) serveSPA(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		http.NotFound(w, r)
		return
	}
	path := strings.TrimPrefix(filepath.Clean(r.URL.Path), "/")
	if path == "." || path == "" {
		path = "index.html"
	}
	b, err := webassets.Read(path)
	if err != nil {
		b, err = webassets.Read("index.html")
	}
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if path == "index.html" {
		lang := a.requestLanguage(r)
		if lang == "en" {
			b = bytes.ReplaceAll(b, []byte(`<html lang="de">`), []byte(`<html lang="en">`))
			b = bytes.ReplaceAll(b, []byte(`ZentContainer wird geladen…`), []byte(`ZentContainer is loading…`))
		}
	}
	if ct := mime.TypeByExtension(filepath.Ext(path)); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.Write(b)
}
func writeJSON(w http.ResponseWriter, v any) { writeJSONStatus(w, 200, v) }
func writeJSONStatus(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func writeRawJSON(w http.ResponseWriter, v []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(v)
}
func errorJSON(w http.ResponseWriter, status int, code, msg string) {
	writeJSONStatus(w, status, map[string]any{"error": map[string]any{"code": code, "message": msg}})
}
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	return decodeJSONLimit(w, r, v, 8*1024*1024)
}

func decodeJSONLimit(w http.ResponseWriter, r *http.Request, v any, limit int64) bool {
	defer r.Body.Close()
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		errorJSON(w, 400, "invalid_json", err.Error())
		return false
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		errorJSON(w, 400, "invalid_json", "request body must contain exactly one JSON value")
		return false
	}
	return true
}
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
func asString(v any) string { s, _ := v.(string); return s }
func safeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
