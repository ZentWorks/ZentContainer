package app

import (
	"encoding/json"
	"net/http"
	"strings"
)

func adoptionCompatibility(raw []byte) (string, []string) {
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
	if v := cfg["Entrypoint"]; v != nil {
		if a, ok := v.([]any); !ok || len(a) > 0 {
			reasons = append(reasons, "benutzerdefinierter Entrypoint")
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
			for _, rawEndpoint := range endpoints {
				endpoint, _ := rawEndpoint.(map[string]any)
				if endpoint["IPAMConfig"] != nil {
					reasons = append(reasons, "statische Netzwerk-IP-Konfiguration")
					break
				}
				if opts, ok := endpoint["DriverOpts"].(map[string]any); ok && len(opts) > 0 {
					reasons = append(reasons, "Netzwerk DriverOpts")
					break
				}
			}
		}
	}
	return name, reasons
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
	name, reasons := adoptionCompatibility(raw)
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
