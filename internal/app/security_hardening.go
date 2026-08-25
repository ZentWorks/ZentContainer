package app

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ZentWorks/ZentContainer/internal/auth"
)

const localAccessCodeFile = "local-access.code"

type loginRateEntry struct {
	Failures     int
	WindowStart  time.Time
	BlockedUntil time.Time
	LastSeen     time.Time
}

func (a *App) localAccessCodePath() string {
	return filepath.Join(a.cfg.SecretsDir(), localAccessCodeFile)
}

func (a *App) ensureLocalAccessCode() (string, error) {
	path := a.localAccessCodePath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", err
	}
	if b, err := os.ReadFile(path); err == nil {
		code := strings.TrimSpace(string(b))
		if strings.HasPrefix(code, "ZCL1-") && len(code) >= 24 {
			if err := os.Chmod(path, 0600); err != nil {
				return "", err
			}
			return code, nil
		}
		return "", fmt.Errorf("invalid local access code file: %s", path)
	} else if !os.IsNotExist(err) {
		return "", err
	}
	secret, err := auth.RandomToken(24)
	if err != nil {
		return "", err
	}
	code := "ZCL1-" + secret
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(code+"\n"), 0600); err != nil {
		return "", err
	}
	if err := os.Chmod(tmp, 0600); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return code, nil
}

func (a *App) verifyLocalAccessCode(code string) bool {
	b, err := os.ReadFile(a.localAccessCodePath())
	if err != nil {
		return false
	}
	want := strings.TrimSpace(string(b))
	got := strings.TrimSpace(code)
	return want != "" && got != "" && constantString(want, got)
}

func (a *App) removeLocalAccessCode() {
	_ = os.Remove(a.localAccessCodePath())
}

func (a *App) announceLocalAccessCode() error {
	role := a.db.Role()
	if role == "controller" {
		a.removeLocalAccessCode()
		return nil
	}
	code, err := a.ensureLocalAccessCode()
	if err != nil {
		return err
	}
	if role == "agent" {
		master, _, _ := a.db.GetSetting("master_url")
		if strings.TrimSpace(master) == "" {
			log.Printf("Agent local access code (required to reveal a pairing code): %s", code)
		}
	} else {
		log.Printf("First-run local setup code: %s", code)
	}
	return nil
}

func loginRemoteKey(r *http.Request, username string) string {
	host := strings.TrimSpace(r.RemoteAddr)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "" {
		host = "unknown"
	}
	user := strings.ToLower(strings.TrimSpace(username))
	if len(user) > 128 {
		user = user[:128]
	}
	return host + "|" + user
}

func (a *App) loginRetryAfter(r *http.Request, username string) time.Duration {
	now := time.Now()
	key := loginRemoteKey(r, username)
	a.loginRateMu.Lock()
	defer a.loginRateMu.Unlock()
	if a.loginAttempts == nil {
		a.loginAttempts = map[string]loginRateEntry{}
	}
	for k, e := range a.loginAttempts {
		if now.Sub(e.LastSeen) > 30*time.Minute {
			delete(a.loginAttempts, k)
		}
	}
	e, ok := a.loginAttempts[key]
	if !ok || !now.Before(e.BlockedUntil) {
		return 0
	}
	return time.Until(e.BlockedUntil)
}

func (a *App) recordLoginFailure(r *http.Request, username string) time.Duration {
	now := time.Now()
	key := loginRemoteKey(r, username)
	a.loginRateMu.Lock()
	defer a.loginRateMu.Unlock()
	if a.loginAttempts == nil {
		a.loginAttempts = map[string]loginRateEntry{}
	}
	e := a.loginAttempts[key]
	if e.WindowStart.IsZero() || now.Sub(e.WindowStart) > 10*time.Minute {
		e = loginRateEntry{WindowStart: now}
	}
	e.Failures++
	e.LastSeen = now
	if e.Failures >= 5 {
		step := e.Failures - 5
		if step > 4 {
			step = 4
		}
		block := 30 * time.Second * time.Duration(1<<step)
		if block > 5*time.Minute {
			block = 5 * time.Minute
		}
		e.BlockedUntil = now.Add(block)
	}
	a.loginAttempts[key] = e
	if now.Before(e.BlockedUntil) {
		return time.Until(e.BlockedUntil)
	}
	return 0
}

func (a *App) clearLoginFailures(r *http.Request, username string) {
	key := loginRemoteKey(r, username)
	a.loginRateMu.Lock()
	delete(a.loginAttempts, key)
	a.loginRateMu.Unlock()
}

func setRetryAfter(w http.ResponseWriter, d time.Duration) {
	seconds := int(d.Round(time.Second).Seconds())
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
}
