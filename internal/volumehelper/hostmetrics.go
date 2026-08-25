package volumehelper

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type HostCPU struct {
	UsagePercent float64 `json:"usage_percent"`
	LogicalCPUs  int     `json:"logical_cpus"`
}

type HostMemory struct {
	Total     uint64 `json:"total"`
	Available uint64 `json:"available"`
	Used      uint64 `json:"used"`
	SwapTotal uint64 `json:"swap_total"`
	SwapFree  uint64 `json:"swap_free"`
}

type HostDisk struct {
	Mountpoint string `json:"mountpoint"`
	Filesystem string `json:"filesystem"`
	Source     string `json:"source"`
	Total      uint64 `json:"total"`
	Used       uint64 `json:"used"`
	Available  uint64 `json:"available"`
}

type HostNetwork struct {
	Name     string  `json:"name"`
	RXBytes  uint64  `json:"rx_bytes"`
	TXBytes  uint64  `json:"tx_bytes"`
	RXPerSec float64 `json:"rx_per_sec"`
	TXPerSec float64 `json:"tx_per_sec"`
}

type HostMetrics struct {
	Hostname     string        `json:"hostname"`
	OS           string        `json:"os"`
	Kernel       string        `json:"kernel"`
	Architecture string        `json:"architecture"`
	Uptime       float64       `json:"uptime_seconds"`
	Load1        float64       `json:"load_1"`
	Load5        float64       `json:"load_5"`
	Load15       float64       `json:"load_15"`
	CPU          HostCPU       `json:"cpu"`
	Memory       HostMemory    `json:"memory"`
	Disks        []HostDisk    `json:"disks"`
	Networks     []HostNetwork `json:"networks"`
	CollectedAt  int64         `json:"collected_at"`
}

type cpuSample struct{ idle, total uint64 }
type netSample struct{ rx, tx uint64 }

// CollectHostMetrics reads host metrics directly from a read-only host /proc mount.
// hostRoot is optional; when empty, filesystem capacity discovery is skipped so the
// main ZentContainer process does not need a permanent mount of the host root.
func CollectHostMetrics(proc, hostRoot, hostnamePath, osReleasePath string) (HostMetrics, error) {
	if _, err := os.Stat(proc + "/stat"); err != nil {
		return HostMetrics{}, fmt.Errorf("host proc is unavailable: %w", err)
	}
	firstCPU, logical, _ := readCPU(proc + "/stat")
	firstNet, _ := readNetworks(proc + "/net/dev")
	started := time.Now()
	time.Sleep(250 * time.Millisecond)
	secondCPU, _, _ := readCPU(proc + "/stat")
	secondNet, _ := readNetworks(proc + "/net/dev")
	elapsed := time.Since(started).Seconds()
	if elapsed <= 0 {
		elapsed = .25
	}

	m := HostMetrics{CollectedAt: time.Now().Unix(), Disks: []HostDisk{}, Networks: []HostNetwork{}}
	m.Hostname = strings.TrimSpace(readText(hostnamePath, readText(proc+"/sys/kernel/hostname", "")))
	m.OS = osRelease(osReleasePath)
	m.Kernel = strings.TrimSpace(readText(proc+"/sys/kernel/osrelease", ""))
	m.Architecture = strings.TrimSpace(readText(proc+"/sys/kernel/arch", ""))
	if m.Architecture == "" {
		var u syscall.Utsname
		if syscall.Uname(&u) == nil {
			m.Architecture = chars(u.Machine[:])
		}
	}
	if fields := strings.Fields(readText(proc+"/uptime", "0")); len(fields) > 0 {
		m.Uptime, _ = strconv.ParseFloat(fields[0], 64)
	}
	loads := strings.Fields(readText(proc+"/loadavg", "0 0 0"))
	if len(loads) >= 3 {
		m.Load1, _ = strconv.ParseFloat(loads[0], 64)
		m.Load5, _ = strconv.ParseFloat(loads[1], 64)
		m.Load15, _ = strconv.ParseFloat(loads[2], 64)
	}
	m.CPU.LogicalCPUs = logical
	if dt := secondCPU.total - firstCPU.total; dt > 0 {
		idle := secondCPU.idle - firstCPU.idle
		m.CPU.UsagePercent = (1 - float64(idle)/float64(dt)) * 100
	}
	m.Memory = readMemory(proc + "/meminfo")
	if hostRoot != "" {
		m.Disks = readDisks(proc, hostRoot)
	}

	for name, now := range secondNet {
		if name == "lo" {
			continue
		}
		before := firstNet[name]
		var rxDelta, txDelta uint64
		if now.rx >= before.rx {
			rxDelta = now.rx - before.rx
		}
		if now.tx >= before.tx {
			txDelta = now.tx - before.tx
		}
		m.Networks = append(m.Networks, HostNetwork{Name: name, RXBytes: now.rx, TXBytes: now.tx, RXPerSec: float64(rxDelta) / elapsed, TXPerSec: float64(txDelta) / elapsed})
	}
	return m, nil
}

func readCPU(path string) (cpuSample, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return cpuSample{}, 0, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	var out cpuSample
	logical := 0
	for s.Scan() {
		fs := strings.Fields(s.Text())
		if len(fs) < 5 {
			continue
		}
		if fs[0] == "cpu" {
			var vals []uint64
			for _, x := range fs[1:] {
				v, _ := strconv.ParseUint(x, 10, 64)
				vals = append(vals, v)
				out.total += v
			}
			if len(vals) > 3 {
				out.idle = vals[3]
				if len(vals) > 4 {
					out.idle += vals[4]
				}
			}
		} else if strings.HasPrefix(fs[0], "cpu") {
			if _, e := strconv.Atoi(strings.TrimPrefix(fs[0], "cpu")); e == nil {
				logical++
			}
		}
	}
	return out, logical, s.Err()
}

func readNetworks(path string) (map[string]netSample, error) {
	f, err := os.Open(path)
	if err != nil {
		return map[string]netSample{}, err
	}
	defer f.Close()
	out := map[string]netSample{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		i := strings.Index(line, ":")
		if i < 0 {
			continue
		}
		name := strings.TrimSpace(line[:i])
		fs := strings.Fields(line[i+1:])
		if len(fs) < 9 {
			continue
		}
		rx, _ := strconv.ParseUint(fs[0], 10, 64)
		tx, _ := strconv.ParseUint(fs[8], 10, 64)
		out[name] = netSample{rx, tx}
	}
	return out, s.Err()
}

func readMemory(path string) HostMemory {
	vals := map[string]uint64{}
	f, err := os.Open(path)
	if err != nil {
		return HostMemory{}
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		fs := strings.Fields(s.Text())
		if len(fs) < 2 {
			continue
		}
		k := strings.TrimSuffix(fs[0], ":")
		v, _ := strconv.ParseUint(fs[1], 10, 64)
		vals[k] = v * 1024
	}
	total := vals["MemTotal"]
	avail := vals["MemAvailable"]
	if avail == 0 {
		avail = vals["MemFree"] + vals["Buffers"] + vals["Cached"]
	}
	used := uint64(0)
	if total > avail {
		used = total - avail
	}
	return HostMemory{Total: total, Available: avail, Used: used, SwapTotal: vals["SwapTotal"], SwapFree: vals["SwapFree"]}
}

func readDisks(proc, hostRoot string) []HostDisk {
	path := proc + "/1/mountinfo"
	f, err := os.Open(path)
	if err != nil {
		return []HostDisk{}
	}
	defer f.Close()
	seen := map[string]bool{}
	out := []HostDisk{}
	s := bufio.NewScanner(f)
	allowed := map[string]bool{"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true, "f2fs": true, "bcachefs": true, "nfs": true, "nfs4": true, "cifs": true, "fuseblk": true}
	for s.Scan() {
		fs := strings.Fields(s.Text())
		sep := -1
		for i, x := range fs {
			if x == "-" {
				sep = i
				break
			}
		}
		if sep < 0 || sep+2 >= len(fs) || len(fs) < 5 {
			continue
		}
		mp := unescapeMount(fs[4])
		typ := fs[sep+1]
		src := fs[sep+2]
		if mp != "/" && !allowed[typ] && !strings.HasPrefix(src, "/dev/") {
			continue
		}
		if seen[mp] {
			continue
		}
		seen[mp] = true
		rootPath := filepath.Join(hostRoot, strings.TrimPrefix(mp, "/"))
		if mp == "/" {
			rootPath = hostRoot
		}
		var st syscall.Statfs_t
		if syscall.Statfs(rootPath, &st) != nil {
			continue
		}
		total := uint64(st.Blocks) * uint64(st.Bsize)
		avail := uint64(st.Bavail) * uint64(st.Bsize)
		free := uint64(st.Bfree) * uint64(st.Bsize)
		used := uint64(0)
		if total > free {
			used = total - free
		}
		out = append(out, HostDisk{Mountpoint: mp, Filesystem: typ, Source: src, Total: total, Used: used, Available: avail})
	}
	return out
}

func unescapeMount(s string) string {
	r := strings.NewReplacer(`\\040`, " ", `\\011`, `\t`, `\\012`, `\n`, `\\134`, `\\`)
	return r.Replace(s)
}
func readText(path, fallback string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return fallback
	}
	return string(b)
}
func osRelease(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	vals := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		if i := strings.Index(line, "="); i > 0 {
			vals[line[:i]] = strings.Trim(strings.TrimSpace(line[i+1:]), `"`)
		}
	}
	if vals["PRETTY_NAME"] != "" {
		return vals["PRETTY_NAME"]
	}
	return strings.TrimSpace(vals["NAME"] + " " + vals["VERSION"])
}
func chars(v []int8) string {
	b := make([]byte, 0, len(v))
	for _, c := range v {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}

func volumeSize(path string) (int64, error) {
	var total int64
	err := filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if d.Type().IsRegular() {
			if info, e := d.Info(); e == nil {
				total += info.Size()
			}
		}
		return nil
	})
	return total, err
}

func printVolumeSize(path string) error {
	n, err := volumeSize(path)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(os.Stdout, "{\"bytes\":%d}\n", n)
	return err
}
