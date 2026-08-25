package app

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ZentWorks/ZentContainer/internal/store"
)

type groupInput struct {
	Name    string                       `json:"name"`
	Members []store.ContainerGroupMember `json:"members"`
}

func cleanGroupInput(in groupInput) (groupInput, error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 80 {
		return in, fmt.Errorf("group name must contain 1 to 80 characters")
	}
	seen := map[string]bool{}
	out := make([]store.ContainerGroupMember, 0, len(in.Members))
	if len(in.Members) > 500 {
		return in, fmt.Errorf("a group can contain at most 500 containers")
	}
	for _, m := range in.Members {
		m.HostID = strings.TrimSpace(m.HostID)
		m.ContainerName = strings.TrimSpace(m.ContainerName)
		if m.HostID == "" || m.ContainerName == "" || len(m.HostID) > 128 || len(m.ContainerName) > 255 {
			return in, fmt.Errorf("invalid group member")
		}
		k := m.HostID + "\x00" + m.ContainerName
		if !seen[k] {
			seen[k] = true
			out = append(out, m)
		}
	}
	in.Members = out
	return in, nil
}
func (a *App) validateGroupHosts(in groupInput) error {
	seen := map[string]bool{}
	for _, m := range in.Members {
		if m.HostID == "local" || seen[m.HostID] {
			continue
		}
		seen[m.HostID] = true
		if _, ok, err := a.db.AgentByID(m.HostID); err != nil {
			return err
		} else if !ok {
			return fmt.Errorf("unknown host: %s", m.HostID)
		}
	}
	return nil
}
func (a *App) groupsList(w http.ResponseWriter, r *http.Request) {
	v, err := a.db.ListContainerGroups()
	if err != nil {
		errorJSON(w, 500, "db_error", err.Error())
		return
	}
	writeJSON(w, v)
}
func (a *App) groupCreate(w http.ResponseWriter, r *http.Request) {
	var in groupInput
	if !decodeJSONLimit(w, r, &in, 256<<10) {
		return
	}
	var err error
	if in, err = cleanGroupInput(in); err != nil {
		errorJSON(w, 400, "invalid_group", err.Error())
		return
	}
	if err := a.validateGroupHosts(in); err != nil {
		errorJSON(w, 400, "invalid_group_host", err.Error())
		return
	}
	g, err := a.db.CreateContainerGroup(in.Name, in.Members)
	if err != nil {
		errorJSON(w, 409, "group_create_failed", err.Error())
		return
	}
	a.db.AddAudit(a.currentActor(r), "group.create", strconv.FormatInt(g.ID, 10), g.Name)
	writeJSONStatus(w, 201, g)
}
func (a *App) groupGet(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		errorJSON(w, 400, "invalid_id", "invalid group id")
		return
	}
	g, ok, err := a.db.ContainerGroupByID(id)
	if err != nil {
		errorJSON(w, 500, "db_error", err.Error())
		return
	}
	if !ok {
		errorJSON(w, 404, "group_not_found", "group not found")
		return
	}
	writeJSON(w, g)
}
func (a *App) groupUpdate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		errorJSON(w, 400, "invalid_id", "invalid group id")
		return
	}
	var in groupInput
	if !decodeJSONLimit(w, r, &in, 256<<10) {
		return
	}
	if in, err = cleanGroupInput(in); err != nil {
		errorJSON(w, 400, "invalid_group", err.Error())
		return
	}
	if err := a.validateGroupHosts(in); err != nil {
		errorJSON(w, 400, "invalid_group_host", err.Error())
		return
	}
	if _, ok, _ := a.db.ContainerGroupByID(id); !ok {
		errorJSON(w, 404, "group_not_found", "group not found")
		return
	}
	if err := a.db.UpdateContainerGroup(id, in.Name, in.Members); err != nil {
		errorJSON(w, 409, "group_update_failed", err.Error())
		return
	}
	a.db.AddAudit(a.currentActor(r), "group.update", strconv.FormatInt(id, 10), in.Name)
	g, _, _ := a.db.ContainerGroupByID(id)
	writeJSON(w, g)
}
func (a *App) groupDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		errorJSON(w, 400, "invalid_id", "invalid group id")
		return
	}
	if err := a.db.DeleteContainerGroup(id); err != nil {
		errorJSON(w, 500, "db_error", err.Error())
		return
	}
	a.db.AddAudit(a.currentActor(r), "group.delete", strconv.FormatInt(id, 10), "")
	writeJSON(w, map[string]any{"ok": true})
}

type groupActionResult struct {
	HostID        string `json:"host_id"`
	ContainerName string `json:"container_name"`
	OK            bool   `json:"ok"`
	Error         string `json:"error,omitempty"`
}

func (a *App) groupAction(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		errorJSON(w, 400, "invalid_id", "invalid group id")
		return
	}
	action := r.PathValue("action")
	if action != "start" && action != "stop" && action != "restart" {
		errorJSON(w, 404, "unknown_action", "unknown group action")
		return
	}
	g, ok, err := a.db.ContainerGroupByID(id)
	if err != nil || !ok {
		errorJSON(w, 404, "group_not_found", "group not found")
		return
	}
	ctx := r.Context()
	results := make([]groupActionResult, len(g.Members))
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for i, m := range g.Members {
		wg.Add(1)
		go func(i int, m store.ContainerGroupMember) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				results[i] = groupActionResult{HostID: m.HostID, ContainerName: m.ContainerName, Error: ctx.Err().Error()}
				return
			}
			defer func() { <-sem }()
			res := groupActionResult{HostID: m.HostID, ContainerName: m.ContainerName}
			if m.HostID == "local" {
				if action == "start" || action == "restart" {
					if _, _, applied, failure := a.applyPendingContainerEdit(ctx, m.ContainerName, true); failure != nil {
						res.Error = failure.Msg
						results[i] = res
						return
					} else if applied {
						res.OK = true
						results[i] = res
						return
					}
				}
				if action == "start" {
					if conflicts, e := a.existingContainerPortConflicts(ctx, m.ContainerName); e == nil && len(conflicts) > 0 {
						res.Error = fmt.Sprintf("port %s/%s is already used by %s", conflicts[0].HostPort, conflicts[0].Protocol, conflicts[0].Container)
						results[i] = res
						return
					}
				}
				d, e := a.docker()
				if e == nil {
					e = d.ContainerAction(ctx, m.ContainerName, action)
				}
				if e != nil {
					res.Error = e.Error()
				} else {
					res.OK = true
				}
			} else {
				ag, found, e := a.db.AgentByID(m.HostID)
				if e != nil || !found {
					if e != nil {
						res.Error = e.Error()
					} else {
						res.Error = "host not found"
					}
				} else {
					resp, e := a.agentRequest(ctx, ag, http.MethodPost, "/agent/api/v1/containers/"+url.PathEscape(m.ContainerName)+"/"+action, strings.NewReader("{}"))
					if e != nil {
						res.Error = e.Error()
					} else {
						io.Copy(io.Discard, resp.Body)
						resp.Body.Close()
						if resp.StatusCode >= 200 && resp.StatusCode < 300 {
							res.OK = true
							a.db.TouchAgent(m.HostID)
						} else {
							res.Error = resp.Status
						}
					}
				}
			}
			results[i] = res
		}(i, m)
	}
	wg.Wait()
	okCount := 0
	for _, x := range results {
		if x.OK {
			okCount++
		}
	}
	a.db.AddAudit(a.currentActor(r), "group."+action, g.Name, fmt.Sprintf("%d/%d", okCount, len(results)))
	writeJSON(w, map[string]any{"ok": okCount == len(results), "successful": okCount, "total": len(results), "results": results, "sampled_at": time.Now().UTC().Format(time.RFC3339Nano)})
}
