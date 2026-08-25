package app

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

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
	_ = containerName // name aliases are intentionally preserved
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
	// Older Docker releases may expose a primary custom MAC only in Config.MacAddress.
	if legacyMAC := strings.TrimSpace(asString(config["MacAddress"])); legacyMAC != "" && primary != "" {
		for i := range attachments {
			if attachments[i].Name == primary {
				if strings.TrimSpace(asString(attachments[i].Endpoint["MacAddress"])) == "" {
					attachments[i].Endpoint["MacAddress"] = legacyMAC
				}
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

func connectNetworkSnapshot(ctx context.Context, d *dockerx.Client, container string, snap containerNetworkSnapshot, skipPrimary bool) error {
	for _, attachment := range snap.Attachments {
		if specialNetworkMode(attachment.Name) || (skipPrimary && attachment.Name == snap.Primary) {
			continue
		}
		if err := d.NetworkConnectConfig(ctx, attachment.Name, container, attachment.Endpoint); err != nil {
			return fmt.Errorf("attach network %s: %w", attachment.Name, err)
		}
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

func verifyNetworkSnapshot(raw []byte, snap containerNetworkSnapshot) error {
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
		if want := requestedIP(expected.Endpoint, "IPv4Address"); want != "" {
			got := strings.TrimSpace(asString(actual["IPAddress"]))
			if got != want {
				return fmt.Errorf("network %s IPv4 changed: expected %s, got %s", expected.Name, want, got)
			}
		}
		if want := requestedIP(expected.Endpoint, "IPv6Address"); want != "" {
			got := strings.TrimSpace(asString(actual["GlobalIPv6Address"]))
			if got == "" {
				got = strings.TrimSpace(asString(actual["IPv6Address"]))
			}
			if got != want {
				return fmt.Errorf("network %s IPv6 changed: expected %s, got %s", expected.Name, want, got)
			}
		}
		if want := strings.TrimSpace(asString(expected.Endpoint["MacAddress"])); want != "" {
			got := strings.TrimSpace(asString(actual["MacAddress"]))
			if !strings.EqualFold(got, want) {
				return fmt.Errorf("network %s MAC changed: expected %s, got %s", expected.Name, want, got)
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
	}
	return nil
}

func connectMissingNetworkSnapshot(ctx context.Context, d *dockerx.Client, container string, snap containerNetworkSnapshot) error {
	raw, err := d.ContainerInspect(ctx, container)
	if err != nil {
		return err
	}
	var ci map[string]any
	if err := json.Unmarshal(raw, &ci); err != nil {
		return err
	}
	ns, _ := ci["NetworkSettings"].(map[string]any)
	networks, _ := ns["Networks"].(map[string]any)
	for _, attachment := range snap.Attachments {
		if specialNetworkMode(attachment.Name) {
			continue
		}
		if _, exists := networks[attachment.Name]; exists {
			continue
		}
		if err := d.NetworkConnectConfig(ctx, attachment.Name, container, attachment.Endpoint); err != nil {
			return fmt.Errorf("attach network %s: %w", attachment.Name, err)
		}
	}
	return nil
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
