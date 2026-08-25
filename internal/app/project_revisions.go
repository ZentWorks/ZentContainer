package app

import (
	"net/http"
)

func (a *App) projectRevisions(w http.ResponseWriter, r *http.Request) {
	v, err := a.projects.ListRevisions(r.PathValue("name"))
	if err != nil {
		errorJSON(w, 500, "revision_error", err.Error())
		return
	}
	writeJSON(w, v)
}
func (a *App) projectRevisionGet(w http.ResponseWriter, r *http.Request) {
	v, err := a.projects.GetRevision(r.PathValue("name"), r.PathValue("revision"))
	if err != nil {
		errorJSON(w, 404, "revision_not_found", err.Error())
		return
	}
	writeJSON(w, v)
}
func (a *App) projectRevisionRestore(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	rev := r.PathValue("revision")
	v, err := a.projects.RestoreRevision(name, rev)
	if err != nil {
		errorJSON(w, 400, "revision_restore_failed", err.Error())
		return
	}
	a.db.AddAudit(a.currentActor(r), "project.revision.restore", name, rev)
	writeJSON(w, map[string]any{"ok": true, "revision": v.ID})
}
