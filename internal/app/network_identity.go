package app

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ZentWorks/ZentContainer/internal/dockerx"
)

type networkAttachmentSnapshot struct {
	Name     string
	Endpoint map[string]any
}

type containerNetworkSnapshot struct {
	Primary     string
	Attachments []networkAttachmentSnapshot
}

type networkVerifyPhase int

const (
	networkVerifyStaged networkVerifyPhase = iota
	networkVerifyRuntime
)

func configurableEndpointFromInspect(endpoint map[string]any, containerName, containerID string) map[string]any {
	out := map[string]any{}
	if ipam, ok := endpoint["IPAMConfig"].(map[string]any); ok {
		clean := map[string]any{}
		for _, key := range []string{"IPv4Address", "IPv6Address", "LinkLocalIPs"} {
			if value, exists := ipam[key]; exists && value != nil {
				switch v := value.(type) {
				case string:
					if strings.TrimSpace(v) != "" {
						clean[key] = v
					}
				case []any:
					if len(v) > 0 {
						clean[key] = v
					}
				}
			}
		}
		if len(clean) > 0 {
			out["IPAMConfig"] = clean
		}
	}
	if aliases := stringSliceAny(endpoint["Aliases"]); len(aliases) > 0 {
		filtered := make([]string, 0, len(aliases))
		fullID := strings.TrimSpace(containerID)
		shortID := shortDockerID(fullID)
		for _, alias := range aliases {
			alias = strings.TrimSpace(alias)
			if alias == "" || alias == fullID || alias == shortID {
				continue
			}
			filtered = append(filtered, alias)
		}
		if len(filtered) > 0 {
			out["Aliases"] = filtered
		}
	}
	for _, key := range []string{"Links", "DriverOpts"} {
		if value, exists := endpoint[key]; exists && value != nil {
			switch v := value.(type) {
			case []any:
				if len(v) > 0 {
					out[key] = v
				}
			case map[string]any:
				if len(v) > 0 {
					out[key] = v
				}
			}
		}
	}
	if mac := strings.TrimSpace(asString(endpoint["MacAddress"])); mac != "" {
		out["MacAddress"] = mac
	}
	if priority := int(asFloat(endpoint["GwPriority"])); priority != 0 {
		out["GwPriority"] = priority
	}
	_ = containerName
	return out
}

func networkSnapshotFromInspect(raw []byte) (containerNetworkSnapshot, error) {
	var ci map[string]any
	if err := json.Unmarshal(raw, &ci); err != nil {
		return containerNetworkSnapshot{}, err
	}
	name := strings.TrimPrefix(asString(ci["Name"]), "/")
	id := asString(ci["Id"])
	hostConfig, _ := ci["HostConfig"].(map[string]any)
	config, _ := ci["Config"].(map[string]any)
	networkSettings, _ := ci["NetworkSettings"].(map[string]any)
	networks, _ := networkSettings["Networks"].(map[string]any)
	primary := strings.TrimSpace(asString(hostConfig["NetworkMode"]))
	if primary == "default" {
		if _, ok := networks["bridge"]; ok {
			primary = "bridge"
		}
	}
	if _, ok := networks[primary]; !ok && primary != "" {
		for networkName, rawEndpoint := range networks {
			endpoint, _ := rawEndpoint.(map[string]any)
			if strings.EqualFold(strings.TrimSpace(asString(endpoint["NetworkID"])), primary) {
				primary = networkName
				break
			}
		}
	}
	if primary == "" && len(networks) == 1 {
		for networkName := range networks {
			primary = networkName
		}
	}
	attachments := make([]networkAttachmentSnapshot, 0, len(networks))
	for networkName, rawEndpoint := range networks {
		endpoint, _ := rawEndpoint.(map[string]any)
		attachments = append(attachments, networkAttachmentSnapshot{Name: networkName, Endpoint: configurableEndpointFromInspect(endpoint, name, id)})
	}
	if legacyMAC := strings.TrimSpace(asString(config["MacAddress"])); legacyMAC != "" && primary != "" {
		for i := range attachments {
			if attachments[i].Name == primary && strings.TrimSpace(asString(attachments[i].Endpoint["MacAddress"])) == "" {
				attachments[i].Endpoint["MacAddress"] = legacyMAC
			}
		}
	}
	sort.SliceStable(attachments, func(i, j int) bool {
		if attachments[i].Name == primary {
			return true
		}
		if attachments[j].Name == primary {
			return false
		}
		return attachments[i].Name < attachments[j].Name
	})
	return containerNetworkSnapshot{Primary: primary, Attachments: attachments}, nil
}

func specialNetworkMode(name string) bool {
	return name == "" || name == "host" || name == "none" || strings.HasPrefix(name, "container:")
}

func disconnectNetworkSnapshot(ctx context.Context, d *dockerx.Client, container string, snap containerNetworkSnapshot) error {
	raw, err := d.ContainerInspect(ctx, container)
	if err != nil {
		return err
	}
	var ci map[string]any
	if err := json.Unmarshal(raw, &ci); err != nil {
		return err
	}
	ns, _ := ci["NetworkSettings"].(map[string]any)
	attached, _ := ns["Networks"].(map[string]any)
	disconnected := make([]networkAttachmentSnapshot, 0, len(snap.Attachments))
	for _, attachment := range snap.Attachments {
		if specialNetworkMode(attachment.Name) {
			continue
		}
		if _, exists := attached[attachment.Name]; !exists {
			continue
		}
		if err := d.NetworkDisconnect(ctx, attachment.Name, container, true); err != nil {
			for i := len(disconnected) - 1; i >= 0; i-- {
				_ = d.NetworkConnectConfig(context.Background(), disconnected[i].Name, container, disconnected[i].Endpoint)
			}
			return fmt.Errorf("detach network %s: %w", attachment.Name, err)
		}
		disconnected = append(disconnected, attachment)
	}
	return nil
}

func networkingConfigForCreate(snap containerNetworkSnapshot) map[string]any {
	if specialNetworkMode(snap.Primary) {
		return nil
	}
	for _, attachment := range snap.Attachments {
		if attachment.Name == snap.Primary {
			return map[string]any{"EndpointsConfig": map[string]any{attachment.Name: attachment.Endpoint}}
		}
	}
	return nil
}

func requestedIP(endpoint map[string]any, key string) string {
	ipam, _ := endpoint["IPAMConfig"].(map[string]any)
	return strings.TrimSpace(asString(ipam[key]))
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func actualEndpointIP(actual map[string]any, family string, phase networkVerifyPhase) string {
	var got string
	if family == "IPv4Address" {
		got = strings.TrimSpace(asString(actual["IPAddress"]))
	} else {
		got = strings.TrimSpace(asString(actual["GlobalIPv6Address"]))
		if got == "" {
			got = strings.TrimSpace(asString(actual["IPv6Address"]))
		}
	}
	// Docker/macvlan/ipvlan can keep the requested address only in IPAMConfig
	// until the endpoint is materialized by container start. That is valid for a
	// staged (stopped) container, but runtime verification deliberately requires
	// the effective address assigned by Docker.
	if got == "" && phase == networkVerifyStaged {
		got = requestedIP(actual, family)
	}
	return got
}

func verifyNetworkAttachment(actual map[string]any, expected networkAttachmentSnapshot, phase networkVerifyPhase) error {
	if want := requestedIP(expected.Endpoint, "IPv4Address"); want != "" {
		if got := actualEndpointIP(actual, "IPv4Address", phase); got != want {
			return fmt.Errorf("network %s IPv4 changed: expected %s, got %s", expected.Name, want, got)
		}
	}
	if want := requestedIP(expected.Endpoint, "IPv6Address"); want != "" {
		if got := actualEndpointIP(actual, "IPv6Address", phase); got != want {
			return fmt.Errorf("network %s IPv6 changed: expected %s, got %s", expected.Name, want, got)
		}
	}
	if want := strings.TrimSpace(asString(expected.Endpoint["MacAddress"])); want != "" {
		got := strings.TrimSpace(asString(actual["MacAddress"]))
		// Some drivers only expose the effective MAC after start. Staged
		// verification accepts an empty runtime field because the exact requested
		// endpoint is still present in Docker's configuration; runtime verification
		// below remains strict.
		if got != "" || phase == networkVerifyRuntime {
			if !strings.EqualFold(got, want) {
				return fmt.Errorf("network %s MAC changed: expected %s, got %s", expected.Name, want, got)
			}
		}
	}
	actualAliases := append(stringSliceAny(actual["Aliases"]), stringSliceAny(actual["DNSNames"])...)
	for _, alias := range stringSliceAny(expected.Endpoint["Aliases"]) {
		if !containsString(actualAliases, alias) {
			return fmt.Errorf("network %s alias %s is missing after recreate", expected.Name, alias)
		}
	}
	if wantIPAM, ok := expected.Endpoint["IPAMConfig"].(map[string]any); ok {
		actualIPAM, _ := actual["IPAMConfig"].(map[string]any)
		for _, want := range stringSliceAny(wantIPAM["LinkLocalIPs"]) {
			if !containsString(stringSliceAny(actualIPAM["LinkLocalIPs"]), want) {
				return fmt.Errorf("network %s link-local IP %s is missing after recreate", expected.Name, want)
			}
		}
	}
	for _, want := range stringSliceAny(expected.Endpoint["Links"]) {
		if !containsString(stringSliceAny(actual["Links"]), want) {
			return fmt.Errorf("network %s link %s is missing after recreate", expected.Name, want)
		}
	}
	if wantOpts, ok := expected.Endpoint["DriverOpts"].(map[string]any); ok {
		actualOpts, _ := actual["DriverOpts"].(map[string]any)
		for key, want := range wantOpts {
			if asString(actualOpts[key]) != asString(want) {
				return fmt.Errorf("network %s driver option %s changed after recreate", expected.Name, key)
			}
		}
	}
	if wantPriority := int(asFloat(expected.Endpoint["GwPriority"])); wantPriority != 0 && int(asFloat(actual["GwPriority"])) != wantPriority {
		return fmt.Errorf("network %s gateway priority changed after recreate", expected.Name)
	}
	return nil
}

func verifyNetworkSnapshotPhase(raw []byte, snap containerNetworkSnapshot, phase networkVerifyPhase) error {
	var ci map[string]any
	if err := json.Unmarshal(raw, &ci); err != nil {
		return err
	}
	ns, _ := ci["NetworkSettings"].(map[string]any)
	networks, _ := ns["Networks"].(map[string]any)
	for _, expected := range snap.Attachments {
		if specialNetworkMode(expected.Name) {
			continue
		}
		rawEndpoint, exists := networks[expected.Name]
		if !exists {
			return fmt.Errorf("network %s is missing after recreate", expected.Name)
		}
		actual, _ := rawEndpoint.(map[string]any)
		if err := verifyNetworkAttachment(actual, expected, phase); err != nil {
			return err
		}
	}
	return nil
}

// verifyNetworkSnapshot is the strict runtime verifier retained for callers and
// regression tests. Stopped/new containers should use verifyStagedNetworkSnapshot.
func verifyNetworkSnapshot(raw []byte, snap containerNetworkSnapshot) error {
	return verifyNetworkSnapshotPhase(raw, snap, networkVerifyRuntime)
}

func verifyStagedNetworkSnapshot(raw []byte, snap containerNetworkSnapshot) error {
	return verifyNetworkSnapshotPhase(raw, snap, networkVerifyStaged)
}

func endpointHasIdentity(endpoint map[string]any) bool {
	if requestedIP(endpoint, "IPv4Address") != "" || requestedIP(endpoint, "IPv6Address") != "" || strings.TrimSpace(asString(endpoint["MacAddress"])) != "" {
		return true
	}
	if len(stringSliceAny(endpoint["Aliases"])) > 0 || len(stringSliceAny(endpoint["Links"])) > 0 {
		return true
	}
	if ipam, ok := endpoint["IPAMConfig"].(map[string]any); ok && len(stringSliceAny(ipam["LinkLocalIPs"])) > 0 {
		return true
	}
	if opts, ok := endpoint["DriverOpts"].(map[string]any); ok && len(opts) > 0 {
		return true
	}
	return int(asFloat(endpoint["GwPriority"])) != 0
}

func inspectNetworkMap(raw []byte) (map[string]any, error) {
	var ci map[string]any
	if err := json.Unmarshal(raw, &ci); err != nil {
		return nil, err
	}
	ns, _ := ci["NetworkSettings"].(map[string]any)
	networks, _ := ns["Networks"].(map[string]any)
	if networks == nil {
		networks = map[string]any{}
	}
	return networks, nil
}

// reconcileNetworkSnapshot makes Docker's endpoint configuration converge on
// the saved/requested identity. It is intentionally driver-agnostic and works
// for bridge, user-defined bridge, macvlan and ipvlan. Only endpoints that are
// missing or demonstrably different are disconnected/reconnected.
func reconcileNetworkSnapshot(ctx context.Context, d *dockerx.Client, container string, snap containerNetworkSnapshot, phase networkVerifyPhase) error {
	raw, err := d.ContainerInspect(ctx, container)
	if err != nil {
		return err
	}
	networks, err := inspectNetworkMap(raw)
	if err != nil {
		return err
	}
	for _, expected := range snap.Attachments {
		if specialNetworkMode(expected.Name) {
			continue
		}
		rawActual, exists := networks[expected.Name]
		needsAttach := !exists
		needsReplace := false
		if exists && endpointHasIdentity(expected.Endpoint) {
			actual, _ := rawActual.(map[string]any)
			needsReplace = verifyNetworkAttachment(actual, expected, phase) != nil
		}
		if !needsAttach && !needsReplace {
			continue
		}
		if needsReplace {
			if err := d.NetworkDisconnect(ctx, expected.Name, container, true); err != nil {
				return fmt.Errorf("reconcile network %s detach: %w", expected.Name, err)
			}
		}
		if err := d.NetworkConnectConfig(ctx, expected.Name, container, expected.Endpoint); err != nil {
			return fmt.Errorf("reconcile network %s attach: %w", expected.Name, err)
		}
		// Keep our local view current when multiple networks are reconciled.
		networks[expected.Name] = expected.Endpoint
	}
	raw, err = d.ContainerInspect(ctx, container)
	if err != nil {
		return err
	}
	return verifyStagedNetworkSnapshot(raw, snap)
}

func waitRuntimeNetworkSnapshot(ctx context.Context, d *dockerx.Client, container string, snap containerNetworkSnapshot, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	deadline := time.Now().Add(timeout)
	var last error
	for {
		raw, err := d.ContainerInspect(ctx, container)
		if err == nil {
			err = verifyNetworkSnapshot(raw, snap)
		}
		if err == nil {
			return nil
		}
		last = err
		if time.Now().After(deadline) {
			return last
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(150 * time.Millisecond):
		}
	}
}

// ensureNetworkSnapshot first validates the staged endpoint request. Running
// containers then get strict runtime verification. If a driver ignored or
// delayed an endpoint setting, ZentContainer performs one targeted endpoint
// reconcile and verifies again before accepting the container.
func ensureNetworkSnapshot(ctx context.Context, d *dockerx.Client, container string, snap containerNetworkSnapshot, running bool) error {
	if err := reconcileNetworkSnapshot(ctx, d, container, snap, networkVerifyStaged); err != nil {
		return err
	}
	if !running {
		return nil
	}
	if err := waitRuntimeNetworkSnapshot(ctx, d, container, snap, 2*time.Second); err == nil {
		return nil
	}
	if err := reconcileNetworkSnapshot(ctx, d, container, snap, networkVerifyRuntime); err != nil {
		return err
	}
	return waitRuntimeNetworkSnapshot(ctx, d, container, snap, 5*time.Second)
}

func networkInputsFromSnapshot(snap containerNetworkSnapshot) []containerNetworkInput {
	out := make([]containerNetworkInput, 0, len(snap.Attachments))
	for _, attachment := range snap.Attachments {
		cfg := containerNetworkInput{Name: attachment.Name, IPv4: requestedIP(attachment.Endpoint, "IPv4Address"), IPv6: requestedIP(attachment.Endpoint, "IPv6Address"), MACAddress: strings.TrimSpace(asString(attachment.Endpoint["MacAddress"])), Aliases: stringSliceAny(attachment.Endpoint["Aliases"]), Links: stringSliceAny(attachment.Endpoint["Links"]), GwPriority: int(asFloat(attachment.Endpoint["GwPriority"]))}
		if ipam, ok := attachment.Endpoint["IPAMConfig"].(map[string]any); ok {
			cfg.LinkLocalIPs = stringSliceAny(ipam["LinkLocalIPs"])
		}
		if opts, ok := attachment.Endpoint["DriverOpts"].(map[string]any); ok {
			cfg.DriverOpts = map[string]string{}
			for k, v := range opts {
				cfg.DriverOpts[k] = asString(v)
			}
		}
		out = append(out, cfg)
	}
	return out
}

func networkSnapshotFromInput(in containerInput) containerNetworkSnapshot {
	snap := containerNetworkSnapshot{}
	if len(in.Networks) == 0 {
		return snap
	}
	snap.Primary = in.Networks[0]
	configs := networkConfigMap(in)
	for _, name := range in.Networks {
		endpoint := map[string]any{}
		if cfg, ok := configs[name]; ok {
			b, _ := json.Marshal(endpointSettingsFromInput(cfg))
			_ = json.Unmarshal(b, &endpoint)
		}
		snap.Attachments = append(snap.Attachments, networkAttachmentSnapshot{Name: name, Endpoint: endpoint})
	}
	return snap
}
