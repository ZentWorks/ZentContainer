package app

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/ZentWorks/ZentContainer/internal/dockerx"
)

func adoptionCompatibility(raw []byte) (string, []string) {
	return adoptionCompatibilityWithImage(raw, nil)
}

func adoptionCompatibilityWithImage(raw, imageRaw []byte) (string, []string) {
	var ci map[string]any
	if json.Unmarshal(raw, &ci) != nil {
		return "", []string{"Container-Inspect konnte nicht ausgewertet werden"}
	}
	name := strings.TrimPrefix(asString(ci["Name"]), "/")
	reasons := []string{}
	cfg, _ := ci["Config"].(map[string]any)
	hc, _ := ci["HostConfig"].(map[string]any)
	labels, _ := cfg["Labels"].(map[string]any)
	if strings.TrimSpace(asString(labels["com.docker.compose.project"])) != "" {
		reasons = append(reasons, "Compose-Container werden über ihr Compose-Projekt verwaltet")
	}

	// The editor currently models the common Docker options only. Adoption is
	// intentionally conservative: if a recreation could drop a setting, the
	// container remains externally managed instead of guessing.
	if containerEntrypoint := stringSliceAny(cfg["Entrypoint"]); len(containerEntrypoint) > 0 {
		imageEntrypoint, known := imageDefaultEntrypoint(imageRaw)
		if !known || !stringSlicesEqual(containerEntrypoint, imageEntrypoint) {
			reasons = append(reasons, "Entrypoint weicht vom Image-Standard ab")
		}
	}
	for _, k := range []string{"Domainname", "MacAddress"} {
		if strings.TrimSpace(asString(cfg[k])) != "" {
			reasons = append(reasons, k)
		}
	}
	for _, k := range []string{"Tty", "OpenStdin", "AttachStdin"} {
		if b, _ := cfg[k].(bool); b {
			reasons = append(reasons, k)
		}
	}
	for _, k := range []string{"Privileged", "ReadonlyRootfs", "AutoRemove", "PublishAllPorts"} {
		if b, _ := hc[k].(bool); b {
			reasons = append(reasons, k)
		}
	}
	for _, k := range []string{"CapAdd", "SecurityOpt", "Mounts", "Ulimits", "DnsOptions", "DnsSearch", "GroupAdd", "Links"} {
		if a, ok := hc[k].([]any); ok && len(a) > 0 {
			reasons = append(reasons, k)
		}
	}
	for _, k := range []string{"Sysctls", "Tmpfs", "StorageOpt"} {
		if m, ok := hc[k].(map[string]any); ok && len(m) > 0 {
			reasons = append(reasons, k)
		}
	}
	for _, k := range []string{"CgroupParent", "PidMode", "UTSMode", "UsernsMode"} {
		if strings.TrimSpace(asString(hc[k])) != "" {
			reasons = append(reasons, k)
		}
	}
	if mode := strings.TrimSpace(asString(hc["IpcMode"])); mode != "" && mode != "private" {
		reasons = append(reasons, "IpcMode")
	}
	if mode := asString(hc["NetworkMode"]); strings.HasPrefix(mode, "container:") {
		reasons = append(reasons, "container-gebundener NetworkMode")
	}
	for _, k := range []string{"MemorySwappiness", "CpuPeriod", "CpuQuota", "CpuRealtimePeriod", "CpuRealtimeRuntime", "BlkioWeight"} {
		if n, ok := hc[k].(float64); ok && n != 0 {
			reasons = append(reasons, k)
		}
	}
	if strings.TrimSpace(asString(hc["CpusetMems"])) != "" {
		reasons = append(reasons, "CpusetMems")
	}
	if n, ok := hc["ShmSize"].(float64); ok && n != 0 && n != 64*1024*1024 {
		reasons = append(reasons, "benutzerdefinierte ShmSize")
	}
	if rp, ok := hc["RestartPolicy"].(map[string]any); ok {
		if n, ok := rp["MaximumRetryCount"].(float64); ok && n != 0 {
			reasons = append(reasons, "RestartPolicy MaximumRetryCount")
		}
	}
	if pb, ok := hc["PortBindings"].(map[string]any); ok {
		for _, rawBindings := range pb {
			bindings, _ := rawBindings.([]any)
			for _, rawBinding := range bindings {
				binding, _ := rawBinding.(map[string]any)
				hostIP := strings.TrimSpace(asString(binding["HostIp"]))
				if hostIP != "" && hostIP != "0.0.0.0" {
					reasons = append(reasons, "Port-Bindung an spezielle Host-IP")
					break
				}
			}
		}
	}
	if networks, ok := ci["NetworkSettings"].(map[string]any); ok {
		if endpoints, ok := networks["Networks"].(map[string]any); ok {
			primary := strings.TrimSpace(asString(hc["NetworkMode"]))
			if primary == "default" {
				if _, exists := endpoints["bridge"]; exists {
					primary = "bridge"
				}
			}
			if primary == "" && len(endpoints) == 1 {
				for networkName := range endpoints {
					primary = networkName
				}
			}
			containerName := strings.TrimPrefix(asString(ci["Name"]), "/")
			containerID := asString(ci["Id"])
			for networkName, rawEndpoint := range endpoints {
				endpoint, _ := rawEndpoint.(map[string]any)
				if ipam, ok := endpoint["IPAMConfig"].(map[string]any); ok {
					hasStatic := strings.TrimSpace(asString(ipam["IPv4Address"])) != "" || strings.TrimSpace(asString(ipam["IPv6Address"])) != ""
					// The editor can faithfully preserve a static address on the primary
					// Docker network. Static addresses on additional networks are not yet
					// modeled independently and remain blocked to avoid changing identity.
					if hasStatic && networkName != primary {
						reasons = append(reasons, "statische IP auf zusätzlichem Netzwerk "+networkName)
					}
					if links, ok := ipam["LinkLocalIPs"].([]any); ok && len(links) > 0 {
						reasons = append(reasons, "LinkLocalIPs auf Netzwerk "+networkName)
					}
				}
				if opts, ok := endpoint["DriverOpts"].(map[string]any); ok && len(opts) > 0 {
					reasons = append(reasons, "Netzwerk DriverOpts auf "+networkName)
				}
				if networkName != primary {
					for _, alias := range stringSliceAny(endpoint["Aliases"]) {
						if alias != containerName && alias != containerID && alias != shortDockerID(containerID) {
							reasons = append(reasons, "Netzwerk-Alias auf zusätzlichem Netzwerk "+networkName)
							break
						}
					}
				}
			}
		}
	}
	return name, reasons
}

func stringSliceAny(v any) []string {
	a, ok := v.([]any)
	if !ok {
		if ss, ok := v.([]string); ok {
			return append([]string(nil), ss...)
		}
		return nil
	}
	out := make([]string, 0, len(a))
	for _, x := range a {
		s := asString(x)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func imageDefaultEntrypoint(raw []byte) ([]string, bool) {
	if len(raw) == 0 {
		return nil, false
	}
	var image map[string]any
	if json.Unmarshal(raw, &image) != nil {
		return nil, false
	}
	cfg, ok := image["Config"].(map[string]any)
	if !ok {
		return nil, false
	}
	return stringSliceAny(cfg["Entrypoint"]), true
}

func shortDockerID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func adoptionCompatibilityForDocker(ctx context.Context, d *dockerx.Client, raw []byte) (string, []string) {
	var meta struct {
		Image  string `json:"Image"`
		Config struct {
			Image string `json:"Image"`
		} `json:"Config"`
	}
	_ = json.Unmarshal(raw, &meta)
	imageRef := strings.TrimSpace(meta.Image)
	if imageRef == "" {
		imageRef = strings.TrimSpace(meta.Config.Image)
	}
	var imageRaw []byte
	if imageRef != "" {
		if inspected, inspectErr := d.ImageInspect(ctx, imageRef); inspectErr == nil {
			imageRaw = inspected
		}
	}
	return adoptionCompatibilityWithImage(raw, imageRaw)
}

func (a *App) containerAdopt(w http.ResponseWriter, r *http.Request) {
	d, err := a.docker()
	if err != nil {
		errorJSON(w, 503, "docker_unavailable", err.Error())
		return
	}
	raw, err := d.ContainerInspect(r.Context(), r.PathValue("id"))
	if err != nil {
		errorJSON(w, 502, "docker_error", err.Error())
		return
	}
	name, reasons := adoptionCompatibilityForDocker(r.Context(), d, raw)
	compatible := len(reasons) == 0
	if r.URL.Query().Get("preview") == "1" {
		writeJSON(w, map[string]any{"compatible": compatible, "name": name, "reasons": reasons})
		return
	}
	if !compatible {
		errorJSON(w, 409, "adopt_unsupported", "Container kann nicht sicher übernommen werden: "+strings.Join(reasons, ", "))
		return
	}
	if err := a.db.AdoptContainer(name); err != nil {
		errorJSON(w, 500, "db_error", err.Error())
		return
	}
	a.db.AddAudit(a.currentActor(r), "container.adopt", name, "")
	writeJSON(w, map[string]any{"ok": true, "name": name})
}
