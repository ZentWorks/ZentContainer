package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/ZentWorks/ZentContainer/internal/dockerx"
)

type containerDeleteResource struct {
	Kind      string   `json:"kind"`
	ID        string   `json:"id,omitempty"`
	Name      string   `json:"name"`
	Detail    string   `json:"detail,omitempty"`
	CanDelete bool     `json:"can_delete"`
	UsedBy    []string `json:"used_by,omitempty"`
	Reason    string   `json:"reason,omitempty"`
}

type containerDeletePlanData struct {
	ContainerID string                    `json:"container_id"`
	Name        string                    `json:"name"`
	Volumes     []containerDeleteResource `json:"volumes"`
	Image       *containerDeleteResource  `json:"image,omitempty"`
	Networks    []containerDeleteResource `json:"networks"`
}

type containerDeleteRequest struct {
	Volumes     []string `json:"volumes"`
	RemoveImage bool     `json:"remove_image"`
	Networks    []string `json:"networks"`
}

func containerDisplayName(c dockerx.ContainerSummary) string {
	if len(c.Names) > 0 {
		if n := strings.TrimPrefix(c.Names[0], "/"); n != "" {
			return n
		}
	}
	if len(c.ID) > 12 {
		return c.ID[:12]
	}
	return c.ID
}

func isSystemDockerNetwork(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "bridge", "host", "none":
		return true
	default:
		return false
	}
}

func (a *App) buildContainerDeletePlan(ctx context.Context, id string) (*containerDeletePlanData, error) {
	d, err := a.docker()
	if err != nil {
		return nil, err
	}
	raw, err := d.ContainerInspect(ctx, id)
	if err != nil {
		return nil, err
	}
	var inspect struct {
		ID     string `json:"Id"`
		Name   string `json:"Name"`
		Image  string `json:"Image"`
		Config struct {
			Image string `json:"Image"`
		} `json:"Config"`
		Mounts          []dockerx.Mount `json:"Mounts"`
		NetworkSettings struct {
			Networks map[string]dockerx.Endpoint `json:"Networks"`
		} `json:"NetworkSettings"`
	}
	if err := json.Unmarshal(raw, &inspect); err != nil {
		return nil, err
	}
	if inspect.ID == "" {
		inspect.ID = id
	}
	name := strings.TrimPrefix(inspect.Name, "/")
	if name == "" {
		name = inspect.ID
		if len(name) > 12 {
			name = name[:12]
		}
	}

	containers, err := d.Containers(ctx, true)
	if err != nil {
		return nil, err
	}
	others := make([]dockerx.ContainerSummary, 0, len(containers))
	for _, c := range containers {
		if c.ID == inspect.ID || strings.HasPrefix(c.ID, inspect.ID) || strings.HasPrefix(inspect.ID, c.ID) {
			continue
		}
		others = append(others, c)
	}

	plan := &containerDeletePlanData{ContainerID: inspect.ID, Name: name, Volumes: []containerDeleteResource{}, Networks: []containerDeleteResource{}}

	seenVolumes := map[string]bool{}
	for _, mount := range inspect.Mounts {
		if mount.Type != "volume" || mount.Name == "" || seenVolumes[mount.Name] {
			continue
		}
		seenVolumes[mount.Name] = true
		usedBy := []string{}
		for _, c := range others {
			for _, cm := range c.Mounts {
				if cm.Type == "volume" && cm.Name == mount.Name {
					usedBy = append(usedBy, containerDisplayName(c))
					break
				}
			}
		}
		sort.Strings(usedBy)
		res := containerDeleteResource{Kind: "volume", ID: mount.Name, Name: mount.Name, Detail: mount.Destination, CanDelete: len(usedBy) == 0, UsedBy: usedBy}
		if len(usedBy) > 0 {
			res.Reason = "Wird noch von " + strings.Join(usedBy, ", ") + " verwendet"
		}
		plan.Volumes = append(plan.Volumes, res)
	}
	sort.Slice(plan.Volumes, func(i, j int) bool { return plan.Volumes[i].Name < plan.Volumes[j].Name })

	if inspect.Image != "" {
		usedBy := []string{}
		for _, c := range others {
			if c.ImageID == inspect.Image {
				usedBy = append(usedBy, containerDisplayName(c))
			}
		}
		sort.Strings(usedBy)
		imageName := strings.TrimSpace(inspect.Config.Image)
		if imageName == "" {
			imageName = inspect.Image
		}
		res := &containerDeleteResource{Kind: "image", ID: inspect.Image, Name: imageName, CanDelete: len(usedBy) == 0, UsedBy: usedBy}
		if len(usedBy) > 0 {
			res.Reason = "Wird noch von " + strings.Join(usedBy, ", ") + " verwendet"
		}
		plan.Image = res
	}

	networks, netErr := d.Networks(ctx)
	if netErr == nil {
		byName := map[string]dockerx.Network{}
		for _, n := range networks {
			byName[n.Name] = n
		}
		names := make([]string, 0, len(inspect.NetworkSettings.Networks))
		for netName := range inspect.NetworkSettings.Networks {
			names = append(names, netName)
		}
		sort.Strings(names)
		for _, netName := range names {
			n, ok := byName[netName]
			if !ok || isSystemDockerNetwork(netName) || n.Ingress {
				continue
			}
			usedBy := []string{}
			for containerID, endpoint := range n.Containers {
				if containerID == inspect.ID || strings.HasPrefix(containerID, inspect.ID) || strings.HasPrefix(inspect.ID, containerID) {
					continue
				}
				label := strings.TrimSpace(endpoint.Name)
				if label == "" {
					label = containerID
					if len(label) > 12 {
						label = label[:12]
					}
				}
				usedBy = append(usedBy, label)
			}
			usedBy = uniqueStrings(usedBy)
			sort.Strings(usedBy)
			res := containerDeleteResource{Kind: "network", ID: n.ID, Name: n.Name, Detail: n.Driver, CanDelete: len(usedBy) == 0, UsedBy: usedBy}
			if len(usedBy) > 0 {
				res.Reason = "Noch verbunden mit " + strings.Join(usedBy, ", ")
			}
			plan.Networks = append(plan.Networks, res)
		}
	}
	return plan, nil
}

func (a *App) containerDeletePlan(w http.ResponseWriter, r *http.Request) {
	plan, err := a.buildContainerDeletePlan(r.Context(), r.PathValue("id"))
	if err != nil {
		errorJSON(w, 502, "delete_plan_failed", err.Error())
		return
	}
	writeJSON(w, plan)
}

func selectedDeleteResources(plan *containerDeletePlanData, in containerDeleteRequest) ([]containerDeleteResource, error) {
	selected := []containerDeleteResource{}
	volumeMap := map[string]containerDeleteResource{}
	for _, v := range plan.Volumes {
		volumeMap[v.Name] = v
	}
	for _, name := range in.Volumes {
		v, ok := volumeMap[name]
		if !ok {
			return nil, fmt.Errorf("volume %s is not mounted by this container", name)
		}
		if !v.CanDelete {
			return nil, fmt.Errorf("volume %s cannot be deleted: %s", name, v.Reason)
		}
		selected = append(selected, v)
	}
	if in.RemoveImage {
		if plan.Image == nil {
			return nil, errors.New("container image could not be determined")
		}
		if !plan.Image.CanDelete {
			return nil, fmt.Errorf("image %s cannot be deleted: %s", plan.Image.Name, plan.Image.Reason)
		}
		selected = append(selected, *plan.Image)
	}
	networkMap := map[string]containerDeleteResource{}
	for _, n := range plan.Networks {
		networkMap[n.ID] = n
		networkMap[n.Name] = n
	}
	for _, id := range in.Networks {
		n, ok := networkMap[id]
		if !ok {
			return nil, fmt.Errorf("network %s is not a removable network of this container", id)
		}
		if !n.CanDelete {
			return nil, fmt.Errorf("network %s cannot be deleted: %s", n.Name, n.Reason)
		}
		selected = append(selected, n)
	}
	return selected, nil
}

func decodeOptionalDeleteRequest(r *http.Request) (containerDeleteRequest, error) {
	var in containerDeleteRequest
	if r.Body != nil {
		err := json.NewDecoder(r.Body).Decode(&in)
		if err != nil && !errors.Is(err, io.EOF) {
			return in, err
		}
	}
	q := r.URL.Query()
	if values := q["volume"]; len(values) > 0 {
		in.Volumes = append(in.Volumes, values...)
	}
	if values := q["network"]; len(values) > 0 {
		in.Networks = append(in.Networks, values...)
	}
	if q.Get("remove_image") == "true" {
		in.RemoveImage = true
	}
	// Any destructive cross-resource option must be announced in the query.
	// requiredScopes() uses the same flags before the handler runs, preventing
	// API clients from hiding privileged delete options only in a request body.
	if len(in.Volumes) > 0 && q.Get("remove_volumes") != "true" {
		return in, errors.New("remove_volumes=true is required when deleting volumes")
	}
	if len(in.Networks) > 0 && q.Get("remove_networks") != "true" {
		return in, errors.New("remove_networks=true is required when deleting networks")
	}
	if in.RemoveImage && q.Get("remove_image") != "true" {
		return in, errors.New("remove_image=true is required when deleting the image")
	}
	in.Volumes = uniqueStrings(in.Volumes)
	in.Networks = uniqueStrings(in.Networks)
	return in, nil
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}
