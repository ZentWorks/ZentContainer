package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ZentWorks/ZentContainer/internal/dockerx"
)

type containerPortInput struct {
	Host      string `json:"host"`
	Container string `json:"container"`
	Protocol  string `json:"protocol"`
	HostIP    string `json:"hostIP,omitempty"`
}
type containerVolumeInput struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"readOnly"`
}
type containerDeviceInput struct {
	Host        string `json:"host"`
	Container   string `json:"container"`
	Permissions string `json:"permissions"`
}
type containerExtraHost struct {
	Host    string `json:"host"`
	Address string `json:"address"`
}
type containerNetworkInput struct {
	Name         string            `json:"name"`
	IPv4         string            `json:"ipv4,omitempty"`
	IPv6         string            `json:"ipv6,omitempty"`
	MACAddress   string            `json:"macAddress,omitempty"`
	Aliases      []string          `json:"aliases,omitempty"`
	LinkLocalIPs []string          `json:"linkLocalIPs,omitempty"`
	Links        []string          `json:"links,omitempty"`
	DriverOpts   map[string]string `json:"driverOpts,omitempty"`
	GwPriority   int               `json:"gwPriority,omitempty"`
}

type containerHealthInput struct {
	Type        string `json:"type"`
	Value       string `json:"value"`
	IntervalSec int64  `json:"intervalSec"`
	TimeoutSec  int64  `json:"timeoutSec"`
	Retries     int    `json:"retries"`
	StartSec    int64  `json:"startSec"`
}
type containerInput struct {
	Name                string                  `json:"name"`
	Image               string                  `json:"image"`
	Restart             string                  `json:"restart"`
	WorkingDir          string                  `json:"workingDir"`
	Hostname            string                  `json:"hostname"`
	User                string                  `json:"user"`
	Command             string                  `json:"command"`
	CommandArgs         []string                `json:"commandArgs,omitempty"`
	Entrypoint          []string                `json:"entrypoint,omitempty"`
	Labels              map[string]string       `json:"labels,omitempty"`
	CapAdd              []string                `json:"capAdd,omitempty"`
	CapDrop             []string                `json:"capDrop,omitempty"`
	SecurityOpt         []string                `json:"securityOpt,omitempty"`
	Privileged          bool                    `json:"privileged,omitempty"`
	ReadonlyRootfs      bool                    `json:"readonlyRootfs,omitempty"`
	AutoRemove          bool                    `json:"autoRemove,omitempty"`
	TTY                 bool                    `json:"tty,omitempty"`
	OpenStdin           bool                    `json:"openStdin,omitempty"`
	Init                bool                    `json:"init,omitempty"`
	MemoryMB            int64                   `json:"memoryMB"`
	MemoryReservationMB int64                   `json:"memoryReservationMB"`
	MemorySwapMB        int64                   `json:"memorySwapMB"`
	CPUs                float64                 `json:"cpus"`
	CPUSet              string                  `json:"cpuSet"`
	CPUShares           int64                   `json:"cpuShares"`
	PidsLimit           int64                   `json:"pidsLimit"`
	Env                 map[string]string       `json:"env"`
	Ports               []containerPortInput    `json:"ports"`
	Volumes             []containerVolumeInput  `json:"volumes"`
	Networks            []string                `json:"networks"`
	Network             string                  `json:"network"`
	StaticIPv4          string                  `json:"staticIPv4"`
	StaticIPv6          string                  `json:"staticIPv6"`
	NetworkAliases      []string                `json:"networkAliases"`
	MACAddress          string                  `json:"macAddress,omitempty"`
	NetworkConfigs      []containerNetworkInput `json:"networkConfigs,omitempty"`
	DNS                 []string                `json:"dns"`
	ExtraHosts          []containerExtraHost    `json:"extraHosts"`
	Devices             []containerDeviceInput  `json:"devices"`
	GPUAll              bool                    `json:"gpuAll"`
	Health              containerHealthInput    `json:"health"`
}

var containerNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

func validateContainerName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("container name is required")
	}
	if !containerNamePattern.MatchString(name) {
		return errors.New("invalid container name: use letters, numbers, dot, underscore or dash; the first character must be a letter or number")
	}
	return nil
}

func normalizeIP(value string, wantV6 bool) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return "", fmt.Errorf("invalid IP address: %s", value)
	}
	if wantV6 {
		if ip.To4() != nil {
			return "", fmt.Errorf("expected IPv6 address, got %s", value)
		}
	} else if ip.To4() == nil {
		return "", fmt.Errorf("expected IPv4 address, got %s", value)
	}
	return ip.String(), nil
}

func normalizeMAC(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	hw, err := net.ParseMAC(value)
	if err != nil || len(hw) != 6 {
		return "", fmt.Errorf("invalid MAC address: %s", value)
	}
	allZero := true
	for _, b := range hw {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero || hw[0]&1 != 0 {
		return "", fmt.Errorf("invalid unicast MAC address: %s", value)
	}
	return hw.String(), nil
}

func cleanStringList(values []string) []string {
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

func networkConfigMap(in containerInput) map[string]containerNetworkInput {
	out := make(map[string]containerNetworkInput, len(in.NetworkConfigs))
	for _, cfg := range in.NetworkConfigs {
		if cfg.Name != "" {
			out[cfg.Name] = cfg
		}
	}
	return out
}

func endpointSettingsFromInput(cfg containerNetworkInput) dockerx.EndpointSettings {
	var ipam *dockerx.EndpointIPAMConfig
	if cfg.IPv4 != "" || cfg.IPv6 != "" || len(cfg.LinkLocalIPs) > 0 {
		ipam = &dockerx.EndpointIPAMConfig{IPv4Address: cfg.IPv4, IPv6Address: cfg.IPv6, LinkLocalIPs: append([]string(nil), cfg.LinkLocalIPs...)}
	}
	return dockerx.EndpointSettings{
		IPAMConfig: ipam,
		Links:      append([]string(nil), cfg.Links...),
		Aliases:    append([]string(nil), cfg.Aliases...),
		MacAddress: cfg.MACAddress,
		DriverOpts: cfg.DriverOpts,
		GwPriority: cfg.GwPriority,
	}
}

type hostResourceLimits struct {
	LogicalCPUs int
	MemoryBytes int64
}

func (a *App) hostResourceLimits(ctx context.Context) (hostResourceLimits, error) {
	d, err := a.docker()
	if err != nil {
		return hostResourceLimits{}, err
	}
	raw, err := d.Info(ctx)
	if err != nil {
		return hostResourceLimits{}, err
	}
	var info map[string]any
	if err := json.Unmarshal(raw, &info); err != nil {
		return hostResourceLimits{}, err
	}
	return hostResourceLimits{LogicalCPUs: int(asFloat(info["NCPU"])), MemoryBytes: int64(asFloat(info["MemTotal"]))}, nil
}

func cpuSetMembers(value string) ([]int, error) {
	seen := map[int]bool{}
	for _, part := range strings.Split(strings.TrimSpace(value), ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			bits := strings.SplitN(part, "-", 2)
			if len(bits) != 2 {
				return nil, errors.New("invalid CPU pinning")
			}
			a, e1 := strconv.Atoi(bits[0])
			b, e2 := strconv.Atoi(bits[1])
			if e1 != nil || e2 != nil || a < 0 || b < a {
				return nil, errors.New("invalid CPU pinning")
			}
			for n := a; n <= b; n++ {
				seen[n] = true
			}
		} else {
			n, err := strconv.Atoi(part)
			if err != nil || n < 0 {
				return nil, errors.New("invalid CPU pinning")
			}
			seen[n] = true
		}
	}
	out := make([]int, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Ints(out)
	return out, nil
}

func (a *App) validateContainerResources(ctx context.Context, in containerInput) error {
	limits, err := a.hostResourceLimits(ctx)
	if err != nil {
		return err
	}
	maxMemoryMB := limits.MemoryBytes / 1024 / 1024
	if maxMemoryMB > 0 && in.MemoryMB > maxMemoryMB {
		return fmt.Errorf("RAM limit cannot exceed %d MB available to Docker", maxMemoryMB)
	}
	if maxMemoryMB > 0 && in.MemoryReservationMB > maxMemoryMB {
		return fmt.Errorf("RAM reservation cannot exceed %d MB available to Docker", maxMemoryMB)
	}
	if limits.LogicalCPUs > 0 && in.CPUs > float64(limits.LogicalCPUs) {
		return fmt.Errorf("CPU limit cannot exceed %d logical CPUs available to Docker", limits.LogicalCPUs)
	}
	members, err := cpuSetMembers(in.CPUSet)
	if err != nil {
		return err
	}
	if limits.LogicalCPUs > 0 {
		for _, n := range members {
			if n >= limits.LogicalCPUs {
				return fmt.Errorf("CPU %d is not available; this host exposes CPUs 0-%d", n, limits.LogicalCPUs-1)
			}
		}
	}
	if len(members) > 0 && in.CPUs > float64(len(members)) {
		return fmt.Errorf("CPU limit cannot exceed %d because only %d pinned CPUs are selected", len(members), len(members))
	}
	return nil
}

func normalizeContainerInput(in *containerInput) error {
	in.Name = strings.TrimSpace(in.Name)
	in.Image = strings.TrimSpace(in.Image)
	in.Restart = strings.TrimSpace(in.Restart)
	in.WorkingDir = strings.TrimSpace(in.WorkingDir)
	in.Hostname = strings.TrimSpace(in.Hostname)
	in.User = strings.TrimSpace(in.User)
	in.CPUSet = strings.TrimSpace(in.CPUSet)
	in.CapAdd = cleanStringList(in.CapAdd)
	in.CapDrop = cleanStringList(in.CapDrop)
	in.SecurityOpt = cleanStringList(in.SecurityOpt)
	if in.Labels == nil {
		in.Labels = map[string]string{}
	}
	cleanLabels := make(map[string]string, len(in.Labels))
	for k, v := range in.Labels {
		k = strings.TrimSpace(k)
		if k != "" {
			cleanLabels[k] = v
		}
	}
	in.Labels = cleanLabels
	in.StaticIPv4 = strings.TrimSpace(in.StaticIPv4)
	in.StaticIPv6 = strings.TrimSpace(in.StaticIPv6)
	if err := validateContainerName(in.Name); err != nil {
		return err
	}
	if in.Image == "" {
		return errors.New("image is required")
	}
	if in.Restart == "" {
		in.Restart = "unless-stopped"
	}
	allowedRestart := map[string]bool{"no": true, "always": true, "unless-stopped": true, "on-failure": true}
	if !allowedRestart[in.Restart] {
		return errors.New("invalid restart policy")
	}
	if in.AutoRemove && in.Restart != "no" {
		return errors.New("auto-remove cannot be combined with an automatic restart policy")
	}
	if len(in.Networks) == 0 && strings.TrimSpace(in.Network) != "" {
		in.Networks = []string{strings.TrimSpace(in.Network)}
	}
	seenNet := map[string]bool{}
	cleanNets := make([]string, 0, len(in.Networks))
	for _, n := range in.Networks {
		n = strings.TrimSpace(n)
		if n != "" && !seenNet[n] {
			seenNet[n] = true
			cleanNets = append(cleanNets, n)
		}
	}
	in.Networks = cleanNets
	if len(in.Networks) > 1 {
		for _, name := range in.Networks {
			if name == "host" || name == "none" {
				return fmt.Errorf("network %s cannot be combined with additional networks", name)
			}
		}
	}
	in.MACAddress = strings.TrimSpace(in.MACAddress)
	if len(in.Networks) == 0 && (in.StaticIPv4 != "" || in.StaticIPv6 != "" || in.MACAddress != "" || len(in.NetworkAliases) > 0 || len(in.NetworkConfigs) > 0) {
		return errors.New("network identity settings require at least one network")
	}
	selected := map[string]bool{}
	for _, name := range in.Networks {
		selected[name] = true
	}
	configs := map[string]containerNetworkInput{}
	for _, cfg := range in.NetworkConfigs {
		cfg.Name = strings.TrimSpace(cfg.Name)
		if cfg.Name == "" {
			continue
		}
		if !selected[cfg.Name] {
			return fmt.Errorf("network configuration references unselected network %s", cfg.Name)
		}
		if cfg.Name == "host" || cfg.Name == "none" {
			if strings.TrimSpace(cfg.IPv4) != "" || strings.TrimSpace(cfg.IPv6) != "" || strings.TrimSpace(cfg.MACAddress) != "" || len(cleanStringList(cfg.Aliases)) > 0 || len(cleanStringList(cfg.LinkLocalIPs)) > 0 || len(cleanStringList(cfg.Links)) > 0 || len(cfg.DriverOpts) > 0 || cfg.GwPriority != 0 {
				return fmt.Errorf("network %s does not support endpoint identity settings", cfg.Name)
			}
		}
		if _, exists := configs[cfg.Name]; exists {
			return fmt.Errorf("duplicate network configuration for %s", cfg.Name)
		}
		var err error
		if cfg.IPv4, err = normalizeIP(cfg.IPv4, false); err != nil {
			return fmt.Errorf("network %s: %w", cfg.Name, err)
		}
		if cfg.IPv6, err = normalizeIP(cfg.IPv6, true); err != nil {
			return fmt.Errorf("network %s: %w", cfg.Name, err)
		}
		if cfg.MACAddress, err = normalizeMAC(cfg.MACAddress); err != nil {
			return fmt.Errorf("network %s: %w", cfg.Name, err)
		}
		cfg.Aliases = cleanStringList(cfg.Aliases)
		cfg.Links = cleanStringList(cfg.Links)
		cfg.LinkLocalIPs = cleanStringList(cfg.LinkLocalIPs)
		for i, ip := range cfg.LinkLocalIPs {
			parsed := net.ParseIP(ip)
			if parsed == nil {
				return fmt.Errorf("network %s: invalid link-local IP address: %s", cfg.Name, ip)
			}
			cfg.LinkLocalIPs[i] = parsed.String()
		}
		if cfg.DriverOpts != nil {
			clean := map[string]string{}
			for k, v := range cfg.DriverOpts {
				k = strings.TrimSpace(k)
				if k != "" {
					clean[k] = v
				}
			}
			cfg.DriverOpts = clean
		}
		configs[cfg.Name] = cfg
	}
	if len(in.Networks) > 0 {
		primary := in.Networks[0]
		legacy := configs[primary]
		legacy.Name = primary
		if legacy.IPv4 == "" && in.StaticIPv4 != "" {
			var err error
			legacy.IPv4, err = normalizeIP(in.StaticIPv4, false)
			if err != nil {
				return fmt.Errorf("network %s: %w", primary, err)
			}
		}
		if legacy.IPv6 == "" && in.StaticIPv6 != "" {
			var err error
			legacy.IPv6, err = normalizeIP(in.StaticIPv6, true)
			if err != nil {
				return fmt.Errorf("network %s: %w", primary, err)
			}
		}
		if legacy.MACAddress == "" && in.MACAddress != "" {
			var err error
			legacy.MACAddress, err = normalizeMAC(in.MACAddress)
			if err != nil {
				return fmt.Errorf("network %s: %w", primary, err)
			}
		}
		if len(legacy.Aliases) == 0 && len(in.NetworkAliases) > 0 {
			legacy.Aliases = cleanStringList(in.NetworkAliases)
		}
		if legacy.IPv4 != "" || legacy.IPv6 != "" || legacy.MACAddress != "" || len(legacy.Aliases) > 0 || len(legacy.LinkLocalIPs) > 0 || len(legacy.Links) > 0 || len(legacy.DriverOpts) > 0 || legacy.GwPriority != 0 {
			configs[primary] = legacy
		}
	}
	in.NetworkConfigs = in.NetworkConfigs[:0]
	for _, name := range in.Networks {
		if cfg, ok := configs[name]; ok {
			in.NetworkConfigs = append(in.NetworkConfigs, cfg)
		}
	}
	if len(in.Networks) > 0 {
		if cfg, ok := configs[in.Networks[0]]; ok {
			in.StaticIPv4, in.StaticIPv6, in.MACAddress, in.NetworkAliases = cfg.IPv4, cfg.IPv6, cfg.MACAddress, append([]string(nil), cfg.Aliases...)
		}
	}
	for i := range in.Ports {
		p := &in.Ports[i]
		p.Host = strings.TrimSpace(p.Host)
		p.Container = strings.TrimSpace(p.Container)
		p.Protocol = strings.ToLower(strings.TrimSpace(p.Protocol))
		p.HostIP = strings.TrimSpace(p.HostIP)
		if p.Container == "" && p.Host == "" {
			continue
		}
		cp, err := strconv.Atoi(p.Container)
		if err != nil || cp < 1 || cp > 65535 {
			return fmt.Errorf("invalid container port: %s", p.Container)
		}
		if p.Host != "" {
			hp, err := strconv.Atoi(p.Host)
			if err != nil || hp < 1 || hp > 65535 {
				return fmt.Errorf("invalid host port: %s", p.Host)
			}
		}
		if p.HostIP != "" {
			p.HostIP = strings.Trim(p.HostIP, "[]")
			if net.ParseIP(p.HostIP) == nil {
				return fmt.Errorf("invalid host IP: %s", p.HostIP)
			}
		}
		if p.Protocol == "" {
			p.Protocol = "tcp"
		}
		if p.Protocol != "tcp" && p.Protocol != "udp" && p.Protocol != "sctp" {
			return fmt.Errorf("invalid port protocol: %s", p.Protocol)
		}
	}
	for i := range in.Volumes {
		v := &in.Volumes[i]
		v.Source = strings.TrimSpace(v.Source)
		v.Target = strings.TrimSpace(v.Target)
		if (v.Source == "") != (v.Target == "") {
			return errors.New("volume source and target must both be set")
		}
		if v.Target != "" && !strings.HasPrefix(v.Target, "/") {
			return fmt.Errorf("container volume target must be absolute: %s", v.Target)
		}
	}
	for i := range in.Devices {
		d := &in.Devices[i]
		d.Host = strings.TrimSpace(d.Host)
		d.Container = strings.TrimSpace(d.Container)
		d.Permissions = strings.TrimSpace(d.Permissions)
		if d.Host == "" && d.Container == "" {
			continue
		}
		if !strings.HasPrefix(d.Host, "/dev/") || !strings.HasPrefix(d.Container, "/dev/") {
			return errors.New("device paths must start with /dev/")
		}
		if d.Permissions == "" {
			d.Permissions = "rwm"
		}
	}
	for i := range in.ExtraHosts {
		in.ExtraHosts[i].Host = strings.TrimSpace(in.ExtraHosts[i].Host)
		in.ExtraHosts[i].Address = strings.TrimSpace(in.ExtraHosts[i].Address)
	}
	clean := func(v []string) []string {
		out := []string{}
		seen := map[string]bool{}
		for _, x := range v {
			x = strings.TrimSpace(x)
			if x != "" && !seen[x] {
				seen[x] = true
				out = append(out, x)
			}
		}
		return out
	}
	in.DNS = clean(in.DNS)
	in.NetworkAliases = clean(in.NetworkAliases)
	if in.MemoryMB < 0 || in.MemoryReservationMB < 0 || in.MemorySwapMB < 0 || in.CPUs < 0 || in.CPUShares < 0 || in.PidsLimit < 0 {
		return errors.New("resource limits cannot be negative")
	}
	if in.MemoryMB > 0 && in.MemoryReservationMB > in.MemoryMB {
		return errors.New("memory reservation cannot exceed memory limit")
	}
	if in.MemorySwapMB > 0 && in.MemoryMB > 0 && in.MemorySwapMB < in.MemoryMB {
		return errors.New("memory + swap limit must be at least the RAM limit")
	}
	if in.CPUSet != "" {
		for _, part := range strings.Split(in.CPUSet, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if strings.Contains(part, "-") {
				bits := strings.SplitN(part, "-", 2)
				if len(bits) != 2 {
					return errors.New("invalid CPU pinning")
				}
				a, e1 := strconv.Atoi(bits[0])
				b, e2 := strconv.Atoi(bits[1])
				if e1 != nil || e2 != nil || a < 0 || b < a {
					return errors.New("invalid CPU pinning")
				}
			} else if n, e := strconv.Atoi(part); e != nil || n < 0 {
				return errors.New("invalid CPU pinning")
			}
		}
	}
	in.Health.Type = strings.ToLower(strings.TrimSpace(in.Health.Type))
	in.Health.Value = strings.TrimSpace(in.Health.Value)
	if in.Health.Type != "" && in.Health.Type != "none" {
		if in.Health.Value == "" {
			return errors.New("healthcheck value is required")
		}
		if in.Health.IntervalSec <= 0 {
			in.Health.IntervalSec = 30
		}
		if in.Health.TimeoutSec <= 0 {
			in.Health.TimeoutSec = 5
		}
		if in.Health.Retries <= 0 {
			in.Health.Retries = 3
		}
	}
	return nil
}

func healthConfig(in containerHealthInput) *dockerx.HealthConfig {
	if in.Type == "" || in.Type == "none" || strings.TrimSpace(in.Value) == "" {
		return nil
	}
	cmd := strings.TrimSpace(in.Value)
	switch in.Type {
	case "http":
		cmd = "wget -q --spider " + shellQuote(cmd) + " || exit 1"
	case "tcp":
		parts := strings.SplitN(cmd, ":", 2)
		if len(parts) == 2 {
			cmd = "nc -z " + shellQuote(parts[0]) + " " + shellQuote(parts[1])
		}
	}
	return &dockerx.HealthConfig{Test: []string{"CMD-SHELL", cmd}, Interval: in.IntervalSec * int64(time.Second), Timeout: in.TimeoutSec * int64(time.Second), Retries: in.Retries, StartPeriod: in.StartSec * int64(time.Second)}
}
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }

func buildContainerRequest(in containerInput) dockerx.CreateContainerRequest {
	env := make([]string, 0, len(in.Env))
	for k, v := range in.Env {
		k = strings.TrimSpace(k)
		if k != "" {
			env = append(env, k+"="+v)
		}
	}
	sort.Strings(env)
	pb := map[string][]dockerx.PortBinding{}
	exp := map[string]map[string]any{}
	for _, p := range in.Ports {
		if p.Container == "" {
			continue
		}
		proto := p.Protocol
		if proto == "" {
			proto = "tcp"
		}
		key := p.Container + "/" + proto
		exp[key] = map[string]any{}
		pb[key] = append(pb[key], dockerx.PortBinding{HostIP: p.HostIP, HostPort: p.Host})
	}
	binds := []string{}
	for _, v := range in.Volumes {
		if v.Source == "" || v.Target == "" {
			continue
		}
		mode := ""
		if v.ReadOnly {
			mode = ":ro"
		}
		binds = append(binds, v.Source+":"+v.Target+mode)
	}
	networkMode := ""
	if len(in.Networks) > 0 {
		networkMode = in.Networks[0]
	}
	cmd := append([]string(nil), in.CommandArgs...)
	if len(cmd) == 0 && strings.TrimSpace(in.Command) != "" {
		cmd = strings.Fields(in.Command)
	}
	labels := make(map[string]string, len(in.Labels)+2)
	for k, v := range in.Labels {
		labels[k] = v
	}
	labels["io.zentcontainer.managed"] = "true"
	labels["io.zentcontainer.created-by"] = "zentcontainer"
	hc := dockerx.HostConfig{Binds: binds, PortBindings: pb, RestartPolicy: dockerx.RestartPolicy{Name: in.Restart}, NetworkMode: networkMode, CpusetCpus: in.CPUSet, CpuShares: in.CPUShares, PidsLimit: in.PidsLimit, Dns: in.DNS, CapAdd: append([]string(nil), in.CapAdd...), CapDrop: append([]string(nil), in.CapDrop...), SecurityOpt: append([]string(nil), in.SecurityOpt...), Privileged: in.Privileged, ReadonlyRootfs: in.ReadonlyRootfs, AutoRemove: in.AutoRemove, Init: in.Init}
	if in.MemoryMB > 0 {
		hc.Memory = in.MemoryMB * 1024 * 1024
	}
	if in.MemoryReservationMB > 0 {
		hc.MemoryReservation = in.MemoryReservationMB * 1024 * 1024
	}
	if in.MemorySwapMB > 0 {
		hc.MemorySwap = in.MemorySwapMB * 1024 * 1024
	}
	if in.CPUs > 0 {
		hc.NanoCPUs = int64(in.CPUs * 1_000_000_000)
	}
	for _, x := range in.ExtraHosts {
		if x.Host != "" && x.Address != "" {
			hc.ExtraHosts = append(hc.ExtraHosts, x.Host+":"+x.Address)
		}
	}
	for _, x := range in.Devices {
		if x.Host != "" && x.Container != "" {
			hc.Devices = append(hc.Devices, dockerx.DeviceMapping{PathOnHost: x.Host, PathInContainer: x.Container, CgroupPermissions: x.Permissions})
		}
	}
	if in.GPUAll {
		hc.DeviceRequests = []dockerx.DeviceRequest{{Driver: "", Count: -1, Capabilities: [][]string{{"gpu"}}}}
	}
	req := dockerx.CreateContainerRequest{Image: in.Image, Cmd: cmd, Entrypoint: append([]string(nil), in.Entrypoint...), Env: env, WorkingDir: in.WorkingDir, Hostname: in.Hostname, User: in.User, Tty: in.TTY, OpenStdin: in.OpenStdin, AttachStdin: in.OpenStdin, Labels: labels, ExposedPorts: exp, Healthcheck: healthConfig(in.Health), HostConfig: hc}
	if networkMode != "" {
		if cfg, ok := networkConfigMap(in)[networkMode]; ok {
			endpoint := endpointSettingsFromInput(cfg)
			req.NetworkingConfig = &dockerx.NetworkingConfig{EndpointsConfig: map[string]dockerx.EndpointSettings{networkMode: endpoint}}
			req.MacAddress = cfg.MACAddress // legacy Docker compatibility for the primary endpoint
		}
	}
	return req
}

type portConflict struct {
	HostIP      string `json:"host_ip,omitempty"`
	HostPort    string `json:"host_port"`
	Protocol    string `json:"protocol"`
	Container   string `json:"container"`
	ContainerID string `json:"container_id"`
	Suggestion  string `json:"suggestion,omitempty"`
}

type usedPortBinding struct {
	IP        string
	Port      string
	Protocol  string
	Container dockerx.ContainerSummary
}

func normalizedHostIP(v string) string {
	v = strings.Trim(strings.TrimSpace(v), "[]")
	if v == "" {
		return "0.0.0.0"
	}
	return v
}

func portBindingIPsConflict(a, b string) bool {
	a, b = normalizedHostIP(a), normalizedHostIP(b)
	if a == b {
		return true
	}
	aIP, bIP := net.ParseIP(a), net.ParseIP(b)
	if aIP == nil || bIP == nil {
		return false
	}
	a4, b4 := aIP.To4() != nil, bIP.To4() != nil
	if a4 != b4 {
		return false
	}
	if a4 {
		return a == "0.0.0.0" || b == "0.0.0.0"
	}
	return a == "::" || b == "::"
}

func (a *App) containerPortConflicts(ctx context.Context, in containerInput, excludeID string) ([]portConflict, error) {
	d, err := a.docker()
	if err != nil {
		return nil, err
	}
	cs, err := d.Containers(ctx, true)
	if err != nil {
		return nil, err
	}
	used := []usedPortBinding{}
	for _, c := range cs {
		if c.ID == excludeID || strings.HasPrefix(c.ID, excludeID) || strings.HasPrefix(excludeID, c.ID) {
			continue
		}
		for _, p := range c.Ports {
			if p.PublicPort > 0 {
				used = append(used, usedPortBinding{IP: p.IP, Port: strconv.Itoa(p.PublicPort), Protocol: strings.ToLower(p.Type), Container: c})
			}
		}
	}
	conflicting := func(ip, port, protocol string) (dockerx.ContainerSummary, bool) {
		for _, u := range used {
			if u.Port == port && u.Protocol == protocol && portBindingIPsConflict(ip, u.IP) {
				return u.Container, true
			}
		}
		return dockerx.ContainerSummary{}, false
	}
	out := []portConflict{}
	for _, p := range in.Ports {
		if p.Host == "" {
			continue
		}
		if c, ok := conflicting(p.HostIP, p.Host, p.Protocol); ok {
			name := strings.TrimPrefix(first(c.Names), "/")
			sug := ""
			hp, _ := strconv.Atoi(p.Host)
			for n := hp + 1; n <= 65535 && n < hp+100; n++ {
				if _, exists := conflicting(p.HostIP, strconv.Itoa(n), p.Protocol); !exists {
					sug = strconv.Itoa(n)
					break
				}
			}
			out = append(out, portConflict{HostIP: p.HostIP, HostPort: p.Host, Protocol: p.Protocol, Container: name, ContainerID: c.ID, Suggestion: sug})
		}
	}
	return out, nil
}

func first(v []string) string {
	if len(v) > 0 {
		return v[0]
	}
	return ""
}
func (a *App) ensureContainerImage(ctx context.Context, d *dockerx.Client, image string) error {
	// Container create/recreate paths prefer an exact local image reference.
	// Registry access is only needed when Docker cannot resolve the requested
	// reference locally. Explicit update/pull operations intentionally bypass
	// this helper and continue to contact the registry.
	if _, err := d.ImageInspect(ctx, image); err == nil {
		return nil
	}
	if _, err := d.ImagePullAuth(ctx, image, a.registryAuthForImage(image)); err != nil {
		return fmt.Errorf("pull image: %w", err)
	}
	return nil
}

func (a *App) createManagedContainer(ctx context.Context, in containerInput, pull bool) (string, error) {
	if err := normalizeContainerInput(&in); err != nil {
		return "", err
	}
	if err := a.validateContainerResources(ctx, in); err != nil {
		return "", err
	}
	d, err := a.docker()
	if err != nil {
		return "", err
	}
	if conflicts, err := a.containerPortConflicts(ctx, in, ""); err != nil {
		return "", err
	} else if len(conflicts) > 0 {
		c := conflicts[0]
		msg := fmt.Sprintf("host port %s/%s is already used by %s", c.HostPort, c.Protocol, c.Container)
		if c.Suggestion != "" {
			msg += "; free suggestion: " + c.Suggestion
		}
		return "", errors.New(msg)
	}
	if pull {
		if err := a.ensureContainerImage(ctx, d, in.Image); err != nil {
			return "", err
		}
	}
	id, err := d.ContainerCreate(ctx, in.Name, buildContainerRequest(in))
	if err != nil {
		return "", err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = d.ContainerRemove(context.Background(), id, true)
		}
	}()
	desiredNetworks := networkSnapshotFromInput(in)
	if err := ensureNetworkSnapshot(ctx, d, id, desiredNetworks, false); err != nil {
		return "", fmt.Errorf("stage network identity: %w", err)
	}
	if err := d.ContainerAction(ctx, id, "start"); err != nil {
		return "", err
	}
	if err := ensureNetworkSnapshot(ctx, d, id, desiredNetworks, true); err != nil {
		return "", fmt.Errorf("verify network identity after start: %w", err)
	}
	cleanup = false
	return id, nil
}

type containerEditFailure struct {
	Status int
	Code   string
	Msg    string
}

func (e *containerEditFailure) Error() string { return e.Msg }
func editFailure(status int, code, msg string) *containerEditFailure {
	return &containerEditFailure{Status: status, Code: code, Msg: msg}
}

func zentContainerStandaloneLabels(labels map[string]string) bool {
	return strings.EqualFold(strings.TrimSpace(labels["io.zentcontainer.managed"]), "true") &&
		strings.EqualFold(strings.TrimSpace(labels["io.zentcontainer.created-by"]), "zentcontainer")
}

type editableContainerState struct {
	Docker          *dockerx.Client
	Name            string
	Managed         bool
	Running         bool
	Labels          map[string]string
	Cmd             []string
	NetworkSnapshot containerNetworkSnapshot
}

func (a *App) validateEditableContainer(ctx context.Context, id string, in *containerInput) (*editableContainerState, *containerEditFailure) {
	if err := normalizeContainerInput(in); err != nil {
		return nil, editFailure(http.StatusBadRequest, "invalid_container", err.Error())
	}
	if err := a.validateContainerResources(ctx, *in); err != nil {
		return nil, editFailure(http.StatusBadRequest, "invalid_resources", err.Error())
	}
	d, err := a.docker()
	if err != nil {
		return nil, editFailure(http.StatusServiceUnavailable, "docker_unavailable", err.Error())
	}
	raw, err := d.ContainerInspect(ctx, id)
	if err != nil {
		return nil, editFailure(http.StatusBadGateway, "docker_error", err.Error())
	}
	var old struct {
		Name   string `json:"Name"`
		Config struct {
			Labels map[string]string `json:"Labels"`
			Cmd    []string          `json:"Cmd"`
		} `json:"Config"`
		State struct {
			Running bool `json:"Running"`
		} `json:"State"`
	}
	if err := json.Unmarshal(raw, &old); err != nil {
		return nil, editFailure(http.StatusInternalServerError, "decode_error", err.Error())
	}
	if old.Config.Labels == nil {
		old.Config.Labels = map[string]string{}
	}
	// API clients that do not send the newer per-network identity model must
	// not silently erase existing static IPs, MAC addresses, aliases or other
	// endpoint settings. Preserve only selected networks that were omitted; an
	// explicit networkConfigs entry (even with empty values) remains authoritative.
	if snap, snapErr := networkSnapshotFromInspect(raw); snapErr == nil {
		existingConfigs := networkConfigMap(*in)
		selected := map[string]bool{}
		for _, networkName := range in.Networks {
			selected[networkName] = true
		}
		for _, cfg := range networkInputsFromSnapshot(snap) {
			if selected[cfg.Name] {
				if _, provided := existingConfigs[cfg.Name]; !provided {
					in.NetworkConfigs = append(in.NetworkConfigs, cfg)
				}
			}
		}
		if err := normalizeContainerInput(in); err != nil {
			return nil, editFailure(http.StatusBadRequest, "invalid_container", err.Error())
		}
	}
	standalone := zentContainerStandaloneLabels(old.Config.Labels)
	if project := strings.TrimSpace(old.Config.Labels["com.docker.compose.project"]); project != "" && !standalone {
		return nil, editFailure(http.StatusConflict, "compose_managed", "This container is managed by Compose project "+project+". Edit the project instead.")
	}
	oldName := strings.TrimPrefix(old.Name, "/")
	managed := strings.EqualFold(strings.TrimSpace(old.Config.Labels["io.zentcontainer.managed"]), "true")
	if !managed && !a.db.IsContainerAdopted(oldName) {
		return nil, editFailure(http.StatusConflict, "external_container", "This container was created outside ZentContainer. Adopt it first before editing.")
	}
	if !managed {
		if _, reasons := adoptionCompatibilityForDocker(ctx, d, raw); len(reasons) > 0 {
			return nil, editFailure(http.StatusConflict, "adopted_container_changed", "Container settings changed outside ZentContainer and can no longer be edited safely: "+strings.Join(reasons, ", "))
		}
	}
	if in.Name == "" {
		in.Name = oldName
	}
	if in.Name != oldName {
		return nil, editFailure(http.StatusBadRequest, "rename_not_supported", "Rename the container separately; editing keeps the current container name")
	}
	if conflicts, err := a.containerPortConflicts(ctx, *in, id); err != nil {
		return nil, editFailure(http.StatusBadGateway, "port_check_failed", err.Error())
	} else if len(conflicts) > 0 {
		c := conflicts[0]
		detail := fmt.Sprintf("Port %s/%s wird bereits von %s verwendet.", c.HostPort, c.Protocol, c.Container)
		if c.Suggestion != "" {
			detail += " Freier Vorschlag: " + c.Suggestion
		}
		return nil, editFailure(http.StatusConflict, "port_conflict", detail)
	}
	// Preserve the exact argv if the visible command was not changed.
	if len(in.CommandArgs) == 0 && in.Command == strings.Join(old.Config.Cmd, " ") {
		in.CommandArgs = append([]string(nil), old.Config.Cmd...)
	}
	networkSnapshot, snapErr := networkSnapshotFromInspect(raw)
	if snapErr != nil {
		return nil, editFailure(http.StatusInternalServerError, "network_snapshot_failed", snapErr.Error())
	}
	return &editableContainerState{Docker: d, Name: oldName, Managed: managed, Running: old.State.Running, Labels: old.Config.Labels, Cmd: old.Config.Cmd, NetworkSnapshot: networkSnapshot}, nil
}

func (a *App) recreateEditableContainer(ctx context.Context, id string, in containerInput, forceStart bool) (string, string, *containerEditFailure) {
	old, failure := a.validateEditableContainer(ctx, id, &in)
	if failure != nil {
		return "", "", failure
	}
	d := old.Docker
	if err := a.ensureContainerImage(ctx, d, in.Image); err != nil {
		return "", old.Name, editFailure(http.StatusBadGateway, "pull_failed", err.Error())
	}
	if old.Running {
		if err := d.ContainerAction(ctx, id, "stop"); err != nil {
			return "", old.Name, editFailure(http.StatusBadGateway, "stop_failed", err.Error())
		}
	}
	backup := "zc-edit-backup-" + safeName(old.Name) + "-" + strconv.FormatInt(time.Now().Unix(), 10)
	if err := d.ContainerRename(ctx, id, backup); err != nil {
		if old.Running {
			_ = d.ContainerAction(context.Background(), id, "start")
		}
		return "", old.Name, editFailure(http.StatusBadGateway, "backup_failed", err.Error())
	}
	restoreOld := func() string {
		parts := []string{}
		bg, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := d.ContainerRename(bg, id, old.Name); err != nil {
			parts = append(parts, "rename: "+err.Error())
		}
		if err := ensureNetworkSnapshot(bg, d, id, old.NetworkSnapshot, false); err != nil {
			parts = append(parts, "network restore: "+err.Error())
		}
		if old.Running {
			if err := d.ContainerAction(bg, id, "start"); err != nil {
				parts = append(parts, "start: "+err.Error())
			} else if err := ensureNetworkSnapshot(bg, d, id, old.NetworkSnapshot, true); err != nil {
				parts = append(parts, "network verify: "+err.Error())
			}
		}
		return strings.Join(parts, "; ")
	}
	if err := disconnectNetworkSnapshot(ctx, d, id, old.NetworkSnapshot); err != nil {
		warn := restoreOld()
		msg := "Could not release the previous network identity: " + err.Error()
		if warn != "" {
			msg += "; restore warning: " + warn
		}
		return "", old.Name, editFailure(http.StatusBadGateway, "network_handoff_failed", msg)
	}
	req := buildContainerRequest(in)
	if !old.Managed {
		for k, v := range old.Labels {
			if _, exists := req.Labels[k]; !exists {
				req.Labels[k] = v
			}
		}
	}
	newID, err := d.ContainerCreate(ctx, in.Name, req)
	if err != nil {
		warn := restoreOld()
		msg := err.Error()
		if warn != "" {
			msg += "; previous container restore warning: " + warn
		}
		return "", old.Name, editFailure(http.StatusBadGateway, "recreate_failed", msg)
	}
	failed := true
	defer func() {
		if failed {
			_ = d.ContainerRemove(context.Background(), newID, true)
		}
	}()
	desiredNetworks := networkSnapshotFromInput(in)
	rollbackNew := func(code, msg string) (string, string, *containerEditFailure) {
		_ = d.ContainerRemove(context.Background(), newID, true)
		failed = false
		warn := restoreOld()
		if warn != "" {
			msg += "; previous container restore warning: " + warn
		}
		return "", old.Name, editFailure(http.StatusBadGateway, code, msg)
	}
	if err := ensureNetworkSnapshot(ctx, d, newID, desiredNetworks, false); err != nil {
		return rollbackNew("network_attach_failed", "Replacement could not stage its network identity: "+err.Error())
	}
	shouldStart := old.Running || forceStart
	if shouldStart {
		if err := d.ContainerAction(ctx, newID, "start"); err != nil {
			return rollbackNew("start_failed", "Replacement failed: "+err.Error())
		}
		if err := ensureNetworkSnapshot(ctx, d, newID, desiredNetworks, true); err != nil {
			return rollbackNew("network_verify_failed", "Replacement network identity verification failed after start: "+err.Error())
		}
	}
	failed = false
	_ = d.ContainerRemove(context.Background(), id, true)
	return newID, old.Name, nil
}

func (a *App) applyPendingContainerEdit(ctx context.Context, id string, forceStart bool) (string, string, bool, *containerEditFailure) {
	d, err := a.docker()
	if err != nil {
		return "", "", false, editFailure(http.StatusServiceUnavailable, "docker_unavailable", err.Error())
	}
	raw, err := d.ContainerInspect(ctx, id)
	if err != nil {
		return "", "", false, editFailure(http.StatusBadGateway, "docker_error", err.Error())
	}
	var meta struct {
		Name string `json:"Name"`
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		return "", "", false, editFailure(http.StatusInternalServerError, "decode_error", err.Error())
	}
	name := strings.TrimPrefix(meta.Name, "/")
	pending, ok, err := a.db.PendingContainerEdit(name)
	if err != nil {
		return "", name, false, editFailure(http.StatusInternalServerError, "pending_edit_failed", err.Error())
	}
	if !ok {
		return id, name, false, nil
	}
	var in containerInput
	if err := json.Unmarshal([]byte(pending.Payload), &in); err != nil {
		return "", name, true, editFailure(http.StatusInternalServerError, "pending_edit_invalid", err.Error())
	}
	newID, oldName, failure := a.recreateEditableContainer(ctx, id, in, forceStart)
	if failure != nil {
		return "", oldName, true, failure
	}
	if err := a.db.DeletePendingContainerEdit(oldName); err != nil {
		return "", oldName, true, editFailure(http.StatusInternalServerError, "pending_edit_cleanup_failed", err.Error())
	}
	return newID, oldName, true, nil
}

func (a *App) containerEdit(w http.ResponseWriter, r *http.Request) {
	var in containerInput
	if !decodeJSON(w, r, &in) {
		return
	}
	old, failure := a.validateEditableContainer(r.Context(), r.PathValue("id"), &in)
	if failure != nil {
		errorJSON(w, failure.Status, failure.Code, failure.Msg)
		return
	}
	apply := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("apply")))
	if apply == "later" {
		payload, err := json.Marshal(in)
		if err != nil {
			errorJSON(w, http.StatusInternalServerError, "encode_error", err.Error())
			return
		}
		if err := a.db.UpsertPendingContainerEdit(old.Name, string(payload)); err != nil {
			errorJSON(w, http.StatusInternalServerError, "pending_edit_failed", err.Error())
			return
		}
		a.db.AddAudit(a.currentActor(r), "container.edit.pending", old.Name, in.Image)
		writeJSON(w, map[string]any{"ok": true, "pending": true, "container_id": r.PathValue("id")})
		return
	}
	newID, oldName, failure := a.recreateEditableContainer(r.Context(), r.PathValue("id"), in, false)
	if failure != nil {
		errorJSON(w, failure.Status, failure.Code, failure.Msg)
		return
	}
	_ = a.db.DeletePendingContainerEdit(oldName)
	a.db.AddAudit(a.currentActor(r), "container.edit", oldName, in.Image)
	writeJSON(w, map[string]any{"ok": true, "container_id": newID})
}
