package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ZentWorks/ZentContainer/internal/dockerx"
)

type externalComposeImageRequest struct {
	Image string `json:"image"`
}

func composeConfigPaths(labels map[string]string) (string, []string, error) {
	workingDir := strings.TrimSpace(labels["com.docker.compose.project.working_dir"])
	rawFiles := strings.TrimSpace(labels["com.docker.compose.project.config_files"])
	if workingDir == "" || rawFiles == "" {
		return "", nil, errors.New("Compose-Arbeitsordner oder Konfigurationsdatei ist nicht in den Docker-Labels hinterlegt")
	}
	if !filepath.IsAbs(workingDir) {
		return "", nil, errors.New("Compose-Arbeitsordner ist kein absoluter Host-Pfad")
	}
	files := []string{}
	for _, raw := range strings.Split(rawFiles, ",") {
		cfg := strings.TrimSpace(raw)
		if cfg == "" {
			continue
		}
		if !filepath.IsAbs(cfg) {
			cfg = filepath.Join(workingDir, cfg)
		}
		rel, err := filepath.Rel(workingDir, cfg)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
			return "", nil, errors.New("Compose-Konfigurationsdatei liegt außerhalb des Arbeitsordners")
		}
		files = append(files, filepath.ToSlash(rel))
	}
	if len(files) == 0 {
		return "", nil, errors.New("keine Compose-Konfigurationsdatei gefunden")
	}
	return filepath.Clean(workingDir), files, nil
}

func (a *App) helperExternalComposeImage(ctx context.Context, workingDir, project, service, image string, configFiles []string) ([]byte, error) {
	d, err := a.docker()
	if err != nil {
		return nil, err
	}
	img, err := a.helperImage(ctx)
	if err != nil {
		return nil, err
	}
	args := []string{"helper", "compose-image", project, service, image}
	args = append(args, configFiles...)
	id, err := d.ContainerCreate(ctx, "", dockerx.CreateContainerRequest{
		Image:      img,
		Cmd:        args,
		WorkingDir: "/workspace",
		HostConfig: dockerx.HostConfig{
			Binds: []string{
				workingDir + ":/workspace:rw",
				a.cfg.DockerSocket + ":/var/run/docker.sock:rw",
			},
			NetworkMode: "none",
		},
	})
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
	out, _ := d.ContainerOutput(ctx, id, 500, false)
	raw, inspectErr := d.ContainerInspect(ctx, id)
	if inspectErr == nil {
		var state struct {
			State struct {
				ExitCode int `json:"ExitCode"`
			} `json:"State"`
		}
		if json.Unmarshal(raw, &state) == nil && state.State.ExitCode != 0 {
			msg := strings.TrimSpace(string(out))
			if msg == "" {
				msg = "Compose konnte nicht aktualisiert werden (Exit " + strconv.Itoa(state.State.ExitCode) + ")"
			}
			return out, errors.New(msg)
		}
	}
	return out, nil
}

func (a *App) containerExternalComposeImage(w http.ResponseWriter, r *http.Request) {
	var in externalComposeImageRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	in.Image = strings.TrimSpace(in.Image)
	if in.Image == "" {
		errorJSON(w, http.StatusBadRequest, "invalid_image", "Image darf nicht leer sein")
		return
	}
	d, err := a.docker()
	if err != nil {
		errorJSON(w, http.StatusServiceUnavailable, "docker_unavailable", err.Error())
		return
	}
	raw, err := d.ContainerInspect(r.Context(), r.PathValue("id"))
	if err != nil {
		errorJSON(w, http.StatusBadGateway, "docker_error", err.Error())
		return
	}
	var ci struct {
		Config struct {
			Image  string            `json:"Image"`
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if err := json.Unmarshal(raw, &ci); err != nil {
		errorJSON(w, http.StatusInternalServerError, "decode_error", err.Error())
		return
	}
	labels := ci.Config.Labels
	project := strings.TrimSpace(labels["com.docker.compose.project"])
	service := strings.TrimSpace(labels["com.docker.compose.service"])
	if project == "" || service == "" {
		errorJSON(w, http.StatusConflict, "not_compose", "Container gehört zu keinem erkennbaren Compose-Service")
		return
	}
	if _, err := a.projects.Get(project); err == nil {
		errorJSON(w, http.StatusConflict, "managed_project", "Dieses Compose-Projekt wird bereits von ZentContainer verwaltet. Öffne das Projekt und ändere dort das Image.")
		return
	}
	workingDir, files, err := composeConfigPaths(labels)
	if err != nil {
		errorJSON(w, http.StatusConflict, "compose_source_unavailable", err.Error())
		return
	}
	out, err := a.helperExternalComposeImage(r.Context(), workingDir, project, service, in.Image, files)
	if err != nil {
		errorJSON(w, http.StatusBadGateway, "compose_update_failed", err.Error())
		return
	}
	a.db.AddAudit(a.currentActor(r), "container.compose-image", project+"/"+service, ci.Config.Image+" -> "+in.Image)
	writeJSON(w, map[string]any{"ok": true, "project": project, "service": service, "image": in.Image, "output": strings.TrimSpace(string(out))})
}
