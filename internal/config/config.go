package config

import (
	"os"
	"path/filepath"
	"strconv"
	"time"
)

type Config struct {
	DataDir      string
	ListenAddr   string
	AgentListen  string
	CookieSecure bool
	SessionTTL   time.Duration
	DockerSocket string
	PublicURL    string
}

func Load() Config {
	data := getenv("ZC_DATA_DIR", "/opt/zentcontainer")
	return Config{
		DataDir:      data,
		ListenAddr:   getenv("ZC_LISTEN", ":9443"),
		AgentListen:  getenv("ZC_AGENT_LISTEN", ":9444"),
		CookieSecure: getenvBool("ZC_COOKIE_SECURE", false),
		SessionTTL:   24 * time.Hour,
		DockerSocket: getenv("ZC_DOCKER_SOCKET", "/var/run/docker.sock"),
		PublicURL:    os.Getenv("ZC_PUBLIC_URL"),
	}
}

func (c Config) DBPath() string          { return filepath.Join(c.DataDir, "zentcontainer.db") }
func (c Config) ProjectsDir() string     { return filepath.Join(c.DataDir, "projects") }
func (c Config) BackupsDir() string      { return filepath.Join(c.DataDir, "backups") }
func (c Config) SecretsDir() string      { return filepath.Join(c.DataDir, "secrets") }
func (c Config) CertificatesDir() string { return filepath.Join(c.DataDir, "certificates") }
func (c Config) ControllerCAPath() string {
	return filepath.Join(c.CertificatesDir(), "controller-ca.crt")
}
func (c Config) ControllerCAKeyPath() string {
	return filepath.Join(c.CertificatesDir(), "controller-ca.key")
}
func (c Config) ControllerClientCertPath() string {
	return filepath.Join(c.CertificatesDir(), "controller-client.crt")
}
func (c Config) ControllerClientKeyPath() string {
	return filepath.Join(c.CertificatesDir(), "controller-client.key")
}
func (c Config) AgentCertPath() string { return filepath.Join(c.CertificatesDir(), "agent.crt") }
func (c Config) AgentKeyPath() string  { return filepath.Join(c.CertificatesDir(), "agent.key") }

func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func getenvBool(k string, d bool) bool {
	v := os.Getenv(k)
	if v == "" {
		return d
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return d
	}
	return b
}
