package app

import (
	"net/http"
	"strings"
	"time"
)

const languageCookie = "zc_language"

func normalizeUILanguage(v string) string {
	if strings.EqualFold(strings.TrimSpace(v), "en") {
		return "en"
	}
	return "de"
}

func (a *App) requestLanguage(r *http.Request) string {
	if c, err := r.Cookie(languageCookie); err == nil {
		return normalizeUILanguage(c.Value)
	}
	if v, ok, _ := a.db.GetSetting("ui_language"); ok {
		return normalizeUILanguage(v)
	}
	if strings.HasPrefix(strings.ToLower(r.Header.Get("Accept-Language")), "en") {
		return "en"
	}
	return "de"
}

func (a *App) setLanguageCookie(w http.ResponseWriter, language string) {
	http.SetCookie(w, &http.Cookie{Name: languageCookie, Value: normalizeUILanguage(language), Path: "/", HttpOnly: true, Secure: a.cfg.CookieSecure, SameSite: http.SameSiteStrictMode, Expires: time.Now().Add(365 * 24 * time.Hour)})
}

func (a *App) languagePreference(w http.ResponseWriter, r *http.Request) {
	if !sameOriginRequest(r) {
		errorJSON(w, 403, "cross_site_request", "Cross-site request rejected")
		return
	}
	var in struct {
		Language string `json:"language"`
	}
	if !decodeJSONLimit(w, r, &in, 1024) {
		return
	}
	language := normalizeUILanguage(in.Language)
	if in.Language != "de" && in.Language != "en" {
		errorJSON(w, 400, "invalid_language", "language must be de or en")
		return
	}
	a.setLanguageCookie(w, language)
	if a.db.Role() == "agent" {
		_ = a.db.SetSetting("ui_language", language)
	}
	writeJSON(w, map[string]any{"language": language})
}

func (a *App) accountLanguage(w http.ResponseWriter, r *http.Request) {
	ac, ok, err := a.authenticate(r)
	if err != nil {
		errorJSON(w, 503, "auth_backend_unavailable", "Session validation is temporarily unavailable")
		return
	}
	if !ok || ac.IsAPI || ac.User == nil {
		errorJSON(w, 403, "interactive_session_required", "An interactive browser session is required")
		return
	}
	var in struct {
		Language string `json:"language"`
	}
	if !decodeJSONLimit(w, r, &in, 1024) {
		return
	}
	if in.Language != "de" && in.Language != "en" {
		errorJSON(w, 400, "invalid_language", "language must be de or en")
		return
	}
	language := normalizeUILanguage(in.Language)
	if err := a.db.UpdateUserLanguage(ac.User.ID, language); err != nil {
		errorJSON(w, 503, "settings_unavailable", "Language preference could not be saved")
		return
	}
	a.sessionMu.Lock()
	for hash, cached := range a.sessionCache {
		if cached.Actor.User != nil && cached.Actor.User.ID == ac.User.ID {
			cached.Actor.User.Language = language
			a.sessionCache[hash] = cached
		}
	}
	a.sessionMu.Unlock()
	a.setLanguageCookie(w, language)
	a.db.AddAudit(ac.Name, "account.language_changed", "system", language)
	writeJSON(w, map[string]any{"language": language})
}
