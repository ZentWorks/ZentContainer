package volumehelper

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type HostDevice struct {
	Path     string `json:"path"`
	Name     string `json:"name"`
	Category string `json:"category"`
}

func runHardware() error {
	root := "/hostdev"
	out := []HostDevice{}
	seen := map[string]bool{}
	add := func(path, name, category string) {
		if path == "" || seen[path] {
			return
		}
		if _, err := os.Stat(filepath.Join(root, strings.TrimPrefix(path, "/dev/"))); err != nil {
			return
		}
		seen[path] = true
		out = append(out, HostDevice{Path: path, Name: name, Category: category})
	}
	entries, _ := os.ReadDir(root)
	for _, e := range entries {
		n := e.Name()
		switch {
		case strings.HasPrefix(n, "ttyUSB") || strings.HasPrefix(n, "ttyACM"):
			add("/dev/"+n, "USB / Serial · "+n, "serial")
		case strings.HasPrefix(n, "video"):
			add("/dev/"+n, "Video · "+n, "video")
		case strings.HasPrefix(n, "nvidia"):
			add("/dev/"+n, "NVIDIA · "+n, "gpu")
		case n == "kvm":
			add("/dev/kvm", "KVM", "virtualization")
		case n == "tun":
			add("/dev/net/tun", "TUN", "network")
		}
	}
	if ents, err := os.ReadDir(filepath.Join(root, "dri")); err == nil {
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), "card") || strings.HasPrefix(e.Name(), "renderD") {
				add("/dev/dri/"+e.Name(), "GPU / DRI · "+e.Name(), "gpu")
			}
		}
		if len(ents) > 0 {
			add("/dev/dri", "GPU / DRI · gesamtes Gerät", "gpu")
		}
	}
	if _, err := os.Stat(filepath.Join(root, "net", "tun")); err == nil {
		add("/dev/net/tun", "TUN", "network")
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Category == out[j].Category {
			return out[i].Path < out[j].Path
		}
		return out[i].Category < out[j].Category
	})
	return json.NewEncoder(os.Stdout).Encode(out)
}
