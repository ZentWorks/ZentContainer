package volumehelper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ZentWorks/ZentContainer/internal/dockerx"
)

type selfNetAttachment struct {
	Name     string
	Endpoint map[string]any
}

type selfNetSnapshot struct {
	Primary     string
	Attachments []selfNetAttachment
}

func selfString(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

func selfStringSlice(v any) []string {
	out := []string{}
	switch x := v.(type) {
	case []any:
		for _, y := range x {
			if s := strings.TrimSpace(selfString(y)); s != "" {
				out = append(out, s)
			}
		}
	case []string:
		for _, s := range x {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

func selfEndpointConfig(ep map[string]any, containerID string) map[string]any {
	out := map[string]any{}
	if ipam, ok := ep["IPAMConfig"].(map[string]any); ok {
		clean := map[string]any{}
		for _, k := range []string{"IPv4Address", "IPv6Address", "LinkLocalIPs"} {
			if v, ok := ipam[k]; ok && v != nil {
				switch z := v.(type) {
				case string:
					if strings.TrimSpace(z) != "" {
						clean[k] = z
					}
				case []any:
					if len(z) > 0 {
						clean[k] = z
					}
				}
			}
		}
		if len(clean) > 0 {
			out["IPAMConfig"] = clean
		}
	}
	shortID := containerID
	if len(shortID) > 12 {
		shortID = shortID[:12]
	}
	aliases := []string{}
	for _, a := range selfStringSlice(ep["Aliases"]) {
		if a != containerID && a != shortID {
			aliases = append(aliases, a)
		}
	}
	if len(aliases) > 0 {
		out["Aliases"] = aliases
	}
	for _, k := range []string{"Links", "DriverOpts"} {
		if v, ok := ep[k]; ok && v != nil {
			out[k] = v
		}
	}
	if mac := strings.TrimSpace(selfString(ep["MacAddress"])); mac != "" {
		out["MacAddress"] = mac
	}
	if p, ok := ep["GwPriority"]; ok && p != nil {
		out["GwPriority"] = p
	}
	return out
}

func selfNetworkSnapshot(raw []byte) (selfNetSnapshot, error) {
	var ci map[string]any
	if err := json.Unmarshal(raw, &ci); err != nil {
		return selfNetSnapshot{}, err
	}
	id := selfString(ci["Id"])
	hc, _ := ci["HostConfig"].(map[string]any)
	ns, _ := ci["NetworkSettings"].(map[string]any)
	nets, _ := ns["Networks"].(map[string]any)
	primary := strings.TrimSpace(selfString(hc["NetworkMode"]))
	if primary == "default" {
		if _, ok := nets["bridge"]; ok {
			primary = "bridge"
		}
	}
	if _, ok := nets[primary]; !ok && primary != "" {
		for name, rawEp := range nets {
			ep, _ := rawEp.(map[string]any)
			if strings.EqualFold(strings.TrimSpace(selfString(ep["NetworkID"])), primary) {
				primary = name
				break
			}
		}
	}
	if primary == "" && len(nets) == 1 {
		for name := range nets {
			primary = name
		}
	}
	snap := selfNetSnapshot{Primary: primary}
	for name, rawEp := range nets {
		ep, _ := rawEp.(map[string]any)
		snap.Attachments = append(snap.Attachments, selfNetAttachment{Name: name, Endpoint: selfEndpointConfig(ep, id)})
	}
	sort.SliceStable(snap.Attachments, func(i, j int) bool {
		if snap.Attachments[i].Name == primary {
			return true
		}
		if snap.Attachments[j].Name == primary {
			return false
		}
		return snap.Attachments[i].Name < snap.Attachments[j].Name
	})
	return snap, nil
}

func selfSpecialNetwork(name string) bool {
	return name == "" || name == "host" || name == "none" || strings.HasPrefix(name, "container:")
}

func selfDisconnectAll(ctx context.Context, d *dockerx.Client, container string, snap selfNetSnapshot) error {
	for _, a := range snap.Attachments {
		if selfSpecialNetwork(a.Name) {
			continue
		}
		if err := d.NetworkDisconnect(ctx, a.Name, container, true); err != nil {
			return fmt.Errorf("detach network %s: %w", a.Name, err)
		}
	}
	return nil
}

func selfNetworkingForCreate(snap selfNetSnapshot) map[string]any {
	if selfSpecialNetwork(snap.Primary) {
		return nil
	}
	for _, a := range snap.Attachments {
		if a.Name == snap.Primary {
			return map[string]any{"EndpointsConfig": map[string]any{a.Name: a.Endpoint}}
		}
	}
	return nil
}

func selfAttachAdditional(ctx context.Context, d *dockerx.Client, container string, snap selfNetSnapshot) error {
	for _, a := range snap.Attachments {
		if selfSpecialNetwork(a.Name) || a.Name == snap.Primary {
			continue
		}
		if err := d.NetworkConnectConfig(ctx, a.Name, container, a.Endpoint); err != nil {
			return fmt.Errorf("attach network %s: %w", a.Name, err)
		}
	}
	return nil
}

func selfVerifyIdentity(raw []byte, snap selfNetSnapshot) error {
	var ci map[string]any
	if err := json.Unmarshal(raw, &ci); err != nil {
		return err
	}
	ns, _ := ci["NetworkSettings"].(map[string]any)
	nets, _ := ns["Networks"].(map[string]any)
	for _, a := range snap.Attachments {
		if selfSpecialNetwork(a.Name) {
			continue
		}
		rawEp, ok := nets[a.Name]
		if !ok {
			return fmt.Errorf("network %s missing after self-update", a.Name)
		}
		ep, _ := rawEp.(map[string]any)
		wantIPAM, _ := a.Endpoint["IPAMConfig"].(map[string]any)
		if want := strings.TrimSpace(selfString(wantIPAM["IPv4Address"])); want != "" && strings.TrimSpace(selfString(ep["IPAddress"])) != want {
			return fmt.Errorf("network %s IPv4 changed", a.Name)
		}
		if want := strings.TrimSpace(selfString(wantIPAM["IPv6Address"])); want != "" {
			got := strings.TrimSpace(selfString(ep["GlobalIPv6Address"]))
			if got == "" {
				got = strings.TrimSpace(selfString(ep["IPv6Address"]))
			}
			if got != want {
				return fmt.Errorf("network %s IPv6 changed", a.Name)
			}
		}
		if want := strings.TrimSpace(selfString(a.Endpoint["MacAddress"])); want != "" && !strings.EqualFold(strings.TrimSpace(selfString(ep["MacAddress"])), want) {
			return fmt.Errorf("network %s MAC changed", a.Name)
		}
	}
	return nil
}

func waitSelfUpdateAck(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat("/tmp/zc-agent-update-ack"); err == nil {
			return nil
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("read Controller acknowledgement: %w", err)
		}
		time.Sleep(500 * time.Millisecond)
	}
	return errors.New("Controller did not reconnect to the updated Agent over mTLS before the safety timeout")
}

func waitComposeServiceReady(project, service, image string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	d, err := dockerx.New("/var/run/docker.sock")
	if err != nil {
		return err
	}
	targetID := ""
	if raw, err := d.ImageInspect(ctx, image); err == nil {
		var im struct {
			ID string `json:"Id"`
		}
		if json.Unmarshal(raw, &im) == nil {
			targetID = strings.TrimSpace(im.ID)
		}
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		items, err := d.Containers(ctx, true)
		if err == nil {
			for _, c := range items {
				if strings.TrimSpace(c.Labels["com.docker.compose.project"]) != project || strings.TrimSpace(c.Labels["com.docker.compose.service"]) != service {
					continue
				}
				if targetID != "" && strings.TrimSpace(c.ImageID) != targetID {
					continue
				}
				raw, ie := d.ContainerInspect(ctx, c.ID)
				if ie != nil {
					continue
				}
				var ci struct {
					State struct {
						Running bool `json:"Running"`
						Health  *struct {
							Status string `json:"Status"`
						} `json:"Health"`
					} `json:"State"`
				}
				if json.Unmarshal(raw, &ci) != nil || !ci.State.Running {
					continue
				}
				if ci.State.Health != nil {
					h := strings.ToLower(strings.TrimSpace(ci.State.Health.Status))
					if h != "healthy" {
						continue
					}
				}
				return nil
			}
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("updated Compose Agent service %s/%s did not become running and healthy", project, service)
}

// runSelfUpdateStandalone performs the destructive portion from a detached helper
// container. The Agent process can therefore disappear without aborting its own
// replacement. The previous container is restored on any failure.
func runSelfUpdateStandalone(args []string) error { return runSelfUpdateStandaloneMode(args, true) }
func runControllerSelfUpdateStandalone(args []string) error {
	return runSelfUpdateStandaloneMode(args, false)
}
func runSelfUpdateStandaloneMode(args []string, requireControllerAck bool) error {
	if len(args) != 3 {
		return errors.New("usage: helper self-update-standalone <container-id> <image> <backup-name>")
	}
	targetID, image, backup := strings.TrimSpace(args[0]), strings.TrimSpace(args[1]), strings.TrimSpace(args[2])
	if targetID == "" || image == "" || backup == "" {
		return errors.New("container id and image are required")
	}
	time.Sleep(2 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	d, err := dockerx.New("/var/run/docker.sock")
	if err != nil {
		return err
	}
	raw, err := d.ContainerInspect(ctx, targetID)
	if err != nil {
		return err
	}
	var ci map[string]any
	if err := json.Unmarshal(raw, &ci); err != nil {
		return err
	}
	name := strings.TrimPrefix(selfString(ci["Name"]), "/")
	if name == "" {
		return errors.New("self container name is empty")
	}
	cfg, _ := ci["Config"].(map[string]any)
	hc, _ := ci["HostConfig"].(map[string]any)
	// Docker's default hostname is the old container ID. Reusing that literal
	// value on the replacement would make future self-inspection point at the
	// rollback container instead of the new Agent. Preserve only an explicitly
	// configured hostname; let Docker generate a fresh default ID hostname.
	if cfg != nil {
		h := strings.TrimSpace(selfString(cfg["Hostname"]))
		shortTarget := targetID
		if len(shortTarget) > 12 {
			shortTarget = shortTarget[:12]
		}
		if h == targetID || h == shortTarget {
			delete(cfg, "Hostname")
		}
	}
	state, _ := ci["State"].(map[string]any)
	running, _ := state["Running"].(bool)
	snap, err := selfNetworkSnapshot(raw)
	if err != nil {
		return err
	}
	if running {
		if err := d.ContainerAction(ctx, targetID, "stop"); err != nil {
			return fmt.Errorf("stop old agent: %w", err)
		}
	}
	if err := d.ContainerRename(ctx, targetID, backup); err != nil {
		if running {
			_ = d.ContainerAction(context.Background(), targetID, "start")
		}
		return fmt.Errorf("rename old agent: %w", err)
	}
	restore := func(reason error) error {
		bg, c := context.WithTimeout(context.Background(), 90*time.Second)
		defer c()
		_ = d.ContainerRename(bg, targetID, name)
		for _, a := range snap.Attachments {
			if !selfSpecialNetwork(a.Name) {
				_ = d.NetworkConnectConfig(bg, a.Name, targetID, a.Endpoint)
			}
		}
		if running {
			_ = d.ContainerAction(bg, targetID, "start")
		}
		if !requireControllerAck {
			clearControllerContinuity(bg, d, targetID)
		}
		return reason
	}
	if err := selfDisconnectAll(ctx, d, targetID, snap); err != nil {
		return restore(err)
	}
	body := map[string]any{}
	for k, v := range cfg {
		body[k] = v
	}
	body["Image"] = image
	body["HostConfig"] = hc
	if netcfg := selfNetworkingForCreate(snap); netcfg != nil {
		body["NetworkingConfig"] = netcfg
	}
	for _, a := range snap.Attachments {
		if a.Name == snap.Primary {
			if mac := strings.TrimSpace(selfString(a.Endpoint["MacAddress"])); mac != "" {
				body["MacAddress"] = mac
			}
			break
		}
	}
	newID, err := d.ContainerCreateMap(ctx, name, body)
	if err != nil {
		return restore(fmt.Errorf("create updated agent: %w", err))
	}
	cleanupNew := func() { _ = d.ContainerRemove(context.Background(), newID, true) }
	if err := selfAttachAdditional(ctx, d, newID, snap); err != nil {
		cleanupNew()
		return restore(err)
	}
	if running {
		if err := d.ContainerAction(ctx, newID, "start"); err != nil {
			cleanupNew()
			return restore(fmt.Errorf("start updated agent: %w", err))
		}
	}
	deadline := time.Now().Add(90 * time.Second)
	for {
		nr, ie := d.ContainerInspect(ctx, newID)
		if ie == nil {
			var ni map[string]any
			_ = json.Unmarshal(nr, &ni)
			st, _ := ni["State"].(map[string]any)
			isRunning, _ := st["Running"].(bool)
			healthy := true
			if h, ok := st["Health"].(map[string]any); ok {
				hs := strings.ToLower(strings.TrimSpace(selfString(h["Status"])))
				healthy = hs == "healthy"
			}
			if (!running || isRunning) && healthy {
				if err := selfVerifyIdentity(nr, snap); err == nil {
					// Do not commit the destructive replacement merely because the process
					// is healthy. Keep the old container as rollback until the Controller
					// has actually reached this replacement over the paired mTLS channel.
					if requireControllerAck {
						if err := waitSelfUpdateAck(6 * time.Minute); err != nil {
							cleanupNew()
							return restore(err)
						}
					} else {
						if err := waitLocalControllerReady(ctx, d, newID, image, 90*time.Second); err != nil {
							cleanupNew()
							return restore(err)
						}
					}
					// The Controller has reached the replacement over mTLS, so the
					// rollback container is no longer needed. Cleanup is best-effort:
					// failure to delete a stopped backup must not undo a verified update.
					if err := d.ContainerRemove(context.Background(), targetID, true); err != nil {
						fmt.Fprintf(os.Stderr, "warning: updated Agent committed but rollback container cleanup failed: %v\n", err)
					}
					return nil
				}
			}
		}
		if time.Now().After(deadline) {
			cleanupNew()
			return restore(errors.New("updated Agent did not become healthy with the preserved network identity"))
		}
		time.Sleep(2 * time.Second)
	}
}

func controllerContinuityConfig() (string, string, error) {
	dbPath := strings.TrimSpace(os.Getenv("ZC_SELFUPDATE_DB_PATH"))
	token := strings.TrimSpace(os.Getenv("ZC_SELFUPDATE_CONTINUITY_TOKEN"))
	if dbPath == "" || token == "" {
		return "", "", errors.New("Controller continuity proof is missing from the self-update helper")
	}
	return dbPath, token, nil
}

func verifyControllerContinuity(ctx context.Context, d *dockerx.Client, container string) error {
	dbPath, token, err := controllerContinuityConfig()
	if err != nil {
		return err
	}
	out, err := d.ExecRun(ctx, container, []string{"sqlite3", dbPath, "SELECT value FROM settings WHERE key='self_update_continuity' LIMIT 1;"})
	if err != nil {
		return fmt.Errorf("replacement cannot read the persistent Controller database: %w", err)
	}
	if strings.TrimSpace(string(out)) != token {
		return errors.New("replacement does not see the previous Controller database; refusing to commit the self-update")
	}
	roleOut, err := d.ExecRun(ctx, container, []string{"sqlite3", dbPath, "SELECT value FROM settings WHERE key='role' LIMIT 1;"})
	if err != nil {
		return fmt.Errorf("replacement cannot verify the persistent Controller role: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(string(roleOut)), "controller") {
		return errors.New("replacement persistent database is not configured as the Controller; refusing to commit the self-update")
	}
	return nil
}

func clearControllerContinuity(ctx context.Context, d *dockerx.Client, container string) {
	dbPath, _, err := controllerContinuityConfig()
	if err != nil {
		return
	}
	_, _ = d.ExecRun(ctx, container, []string{"sqlite3", dbPath, "DELETE FROM settings WHERE key='self_update_continuity';"})
}

func controllerListenPortFromInspect(raw []byte) string {
	var ci struct {
		Config struct {
			Env []string `json:"Env"`
		} `json:"Config"`
	}
	if json.Unmarshal(raw, &ci) != nil {
		return "9443"
	}
	for _, e := range ci.Config.Env {
		if !strings.HasPrefix(e, "ZC_LISTEN=") {
			continue
		}
		v := strings.TrimSpace(strings.TrimPrefix(e, "ZC_LISTEN="))
		if i := strings.LastIndex(v, ":"); i >= 0 && i+1 < len(v) {
			if p := strings.TrimSpace(v[i+1:]); p != "" {
				return p
			}
		}
	}
	return "9443"
}

func waitLocalControllerReady(ctx context.Context, d *dockerx.Client, container, image string, timeout time.Duration) error {
	targetID := ""
	if raw, err := d.ImageInspect(ctx, image); err == nil {
		var im struct {
			ID string `json:"Id"`
		}
		if json.Unmarshal(raw, &im) == nil {
			targetID = strings.TrimSpace(im.ID)
		}
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		raw, err := d.ContainerInspect(ctx, container)
		if err == nil {
			var ci struct {
				Image string `json:"Image"`
				State struct {
					Running bool `json:"Running"`
					Health  *struct {
						Status string `json:"Status"`
					} `json:"Health"`
				} `json:"State"`
			}
			if json.Unmarshal(raw, &ci) == nil && ci.State.Running && (targetID == "" || strings.TrimSpace(ci.Image) == targetID) {
				healthy := ci.State.Health == nil || strings.EqualFold(strings.TrimSpace(ci.State.Health.Status), "healthy")
				if healthy {
					// /api/setup is intentionally reachable on an unconfigured instance, so
					// HTTP health alone must never commit a Controller replacement. Prove
					// that this exact replacement loaded the previous persistent SQLite DB.
					if e := verifyControllerContinuity(ctx, d, container); e != nil {
						return e
					}
					port := controllerListenPortFromInspect(raw)
					if _, e := d.ExecRun(ctx, container, []string{"sh", "-c", fmt.Sprintf("wget -q -O- http://127.0.0.1:%s/api/setup >/dev/null", port)}); e == nil {
						clearControllerContinuity(ctx, d, container)
						return nil
					}
				}
			}
		}
		time.Sleep(2 * time.Second)
	}
	return errors.New("updated ZentContainer did not become healthy, preserve its Controller database, and become reachable through its local HTTP API")
}

func waitComposeControllerReady(project, service, image string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	d, err := dockerx.New("/var/run/docker.sock")
	if err != nil {
		return err
	}
	targetID := ""
	if raw, e := d.ImageInspect(ctx, image); e == nil {
		var im struct {
			ID string `json:"Id"`
		}
		if json.Unmarshal(raw, &im) == nil {
			targetID = strings.TrimSpace(im.ID)
		}
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		items, e := d.Containers(ctx, true)
		if e == nil {
			for _, c := range items {
				if strings.TrimSpace(c.Labels["com.docker.compose.project"]) != project || strings.TrimSpace(c.Labels["com.docker.compose.service"]) != service {
					continue
				}
				if targetID != "" && strings.TrimSpace(c.ImageID) != targetID {
					continue
				}
				if e := waitLocalControllerReady(ctx, d, c.ID, image, 8*time.Second); e == nil {
					return nil
				}
			}
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("updated Compose ZentContainer service %s/%s did not become locally reachable", project, service)
}
