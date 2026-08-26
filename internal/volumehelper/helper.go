package volumehelper

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type Entry struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	IsDir    bool   `json:"is_dir"`
	Size     int64  `json:"size"`
	Mode     string `json:"mode"`
	Modified int64  `json:"modified"`
}

const root = "/mnt/volume"

func Run(args []string) error {
	if len(args) == 0 {
		return errors.New("helper command required")
	}
	if args[0] == "hold" {
		select {}
	}
	if args[0] == "hardware" {
		return runHardware()
	}
	if args[0] == "compose-check" {
		return runComposeCheck(args[1:])
	}
	if args[0] == "compose-image" {
		return runComposeImage(args[1:])
	}
	if args[0] == "self-update-compose" {
		return runSelfUpdateCompose(args[1:])
	}
	if args[0] == "self-update-controller-compose" {
		return runControllerSelfUpdateCompose(args[1:])
	}
	if args[0] == "self-update-standalone" {
		return runSelfUpdateStandalone(args[1:])
	}
	if args[0] == "self-update-controller-standalone" {
		return runControllerSelfUpdateStandalone(args[1:])
	}
	if len(args) < 2 || args[0] != "fs" {
		return errors.New("usage: helper fs <list|delete|mkdir|size|clear> [path]")
	}
	cmd := args[1]
	p := "/"
	if len(args) > 2 {
		p = args[2]
	}
	safe, err := safePath(p, cmd == "mkdir")
	if err != nil {
		return err
	}
	switch cmd {
	case "list":
		items, err := os.ReadDir(safe)
		if err != nil {
			return err
		}
		out := make([]Entry, 0, len(items))
		for _, it := range items {
			info, err := it.Info()
			if err != nil {
				continue
			}
			rel, _ := filepath.Rel(root, filepath.Join(safe, it.Name()))
			out = append(out, Entry{Name: it.Name(), Path: "/" + filepath.ToSlash(rel), IsDir: it.IsDir(), Size: info.Size(), Mode: info.Mode().String(), Modified: info.ModTime().Unix()})
		}
		return json.NewEncoder(os.Stdout).Encode(out)
	case "delete":
		if safe == root {
			return errors.New("refusing to delete volume root")
		}
		return os.RemoveAll(safe)
	case "mkdir":
		return os.MkdirAll(safe, 0755)
	case "size":
		return printVolumeSize(safe)
	case "clear":
		if safe != root {
			return errors.New("clear only supports volume root")
		}
		items, err := os.ReadDir(root)
		if err != nil {
			return err
		}
		for _, it := range items {
			if err := os.RemoveAll(filepath.Join(root, it.Name())); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown fs command %q", cmd)
	}
}
func safePath(p string, allowMissing bool) (string, error) {
	clean := filepath.Clean("/" + strings.TrimSpace(p))
	target := filepath.Join(root, clean)
	baseReal, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	check := target
	if allowMissing {
		check = filepath.Dir(target)
	}
	real, err := filepath.EvalSymlinks(check)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(baseReal, real)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", errors.New("path escapes volume")
	}
	return target, nil
}

func composeServiceImageReplace(data []byte, service, image string) ([]byte, bool) {
	lines := strings.Split(string(data), "\n")
	servicesIndent := -1
	serviceIndent := -1
	serviceStart := -1
	serviceEnd := len(lines)
	for i, line := range lines {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		if servicesIndent < 0 {
			if trim == "services:" {
				servicesIndent = indent
			}
			continue
		}
		if indent <= servicesIndent {
			break
		}
		if serviceStart < 0 {
			if indent > servicesIndent && trim == service+":" {
				serviceIndent = indent
				serviceStart = i
			}
			continue
		}
		if indent <= serviceIndent {
			serviceEnd = i
			break
		}
	}
	if serviceStart < 0 {
		return data, false
	}
	for i := serviceStart + 1; i < serviceEnd; i++ {
		line := lines[i]
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		if indent <= serviceIndent {
			break
		}
		if strings.HasPrefix(trim, "image:") {
			prefix := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
			lines[i] = prefix + "image: " + strconvQuoteYAML(image)
			return []byte(strings.Join(lines, "\n")), true
		}
	}
	return data, false
}

func strconvQuoteYAML(s string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(s, `\\`, `\\\\`), `"`, `\\"`) + `"`
}

func runComposeCheck(args []string) error {
	if len(args) < 2 {
		return errors.New("usage: helper compose-check <service> <compose-file> [compose-file...]")
	}
	service := strings.TrimSpace(args[0])
	if service == "" {
		return errors.New("compose service is required")
	}
	for _, raw := range args[1:] {
		rel := filepath.Clean(raw)
		if filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return errors.New("unsafe compose file path")
		}
		data, err := os.ReadFile(filepath.Join("/workspace", rel))
		if err != nil {
			return fmt.Errorf("read %s: %w", rel, err)
		}
		if _, ok := composeServiceImageReplace(data, service, "__zc_probe_image__"); ok {
			return nil
		}
	}
	return fmt.Errorf("service %s has no editable image entry in the Compose source", service)
}

func runSelfUpdateCompose(args []string) error { return runSelfUpdateComposeMode(args, true) }
func runControllerSelfUpdateCompose(args []string) error {
	return runSelfUpdateComposeMode(args, false)
}
func runSelfUpdateComposeMode(args []string, requireControllerAck bool) error {
	if len(args) < 5 {
		return errors.New("usage: helper self-update-compose <project> <service> <image> <rollback-image-id> <compose-file> [compose-file...]")
	}
	time.Sleep(2 * time.Second)
	rollbackImageID := strings.TrimSpace(args[3])
	composeArgs := append([]string{}, args[:3]...)
	composeArgs = append(composeArgs, args[4:]...)
	return runComposeImageMode(composeArgs, true, rollbackImageID, requireControllerAck)
}

func runComposeImage(args []string) error { return runComposeImageMode(args, false, "", false) }

func runComposeImageMode(args []string, selfUpdate bool, rollbackImageID string, requireControllerAck bool) error {
	if len(args) < 4 {
		return errors.New("usage: helper compose-image <project> <service> <image> <compose-file> [compose-file...]")
	}
	project, service, image := strings.TrimSpace(args[0]), strings.TrimSpace(args[1]), strings.TrimSpace(args[2])
	files := args[3:]
	if project == "" || service == "" || image == "" {
		return errors.New("project, service and image are required")
	}
	var target string
	var original []byte
	for i := len(files) - 1; i >= 0; i-- {
		rel := filepath.Clean(files[i])
		if filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return errors.New("unsafe compose file path")
		}
		path := filepath.Join("/workspace", rel)
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", rel, err)
		}
		updated, ok := composeServiceImageReplace(data, service, image)
		if !ok {
			continue
		}
		target, original = path, data
		if err := os.WriteFile(path, updated, 0644); err != nil {
			return fmt.Errorf("write %s: %w", rel, err)
		}
		break
	}
	if target == "" {
		return fmt.Errorf("service %s has no editable image entry in the Compose source", service)
	}
	composeArgs := []string{"compose", "-p", project}
	for _, f := range files {
		composeArgs = append(composeArgs, "-f", filepath.Join("/workspace", filepath.Clean(f)))
	}
	if selfUpdate {
		composeArgs = append(composeArgs, "up", "-d", "--no-deps", "--no-build", "--force-recreate", service)
	} else {
		composeArgs = append(composeArgs, "up", "-d", service)
	}
	rollbackCompose := func(reason error) error {
		if writeErr := os.WriteFile(target, original, 0644); writeErr != nil {
			return fmt.Errorf("%v; additionally could not restore Compose source: %w", reason, writeErr)
		}
		if selfUpdate && strings.TrimSpace(rollbackImageID) != "" {
			// Pulling :latest moves the tag before Compose recreates the service.
			// Restore the previous image behind the requested reference before
			// re-applying the original Compose source.
			if tagErr := exec.Command("docker", "image", "tag", rollbackImageID, image).Run(); tagErr != nil {
				return fmt.Errorf("%v; Compose source restored but previous Agent image could not be retagged: %w", reason, tagErr)
			}
		}
		rollback := exec.Command("docker", composeArgs...)
		rollback.Dir = "/workspace"
		rbOut, rbErr := rollback.CombinedOutput()
		if len(rbOut) > 0 {
			_, _ = os.Stdout.Write(rbOut)
		}
		if rbErr != nil {
			msg := strings.TrimSpace(string(rbOut))
			if msg != "" {
				return fmt.Errorf("%v; automatic Compose rollback failed: %w: %s", reason, rbErr, msg)
			}
			return fmt.Errorf("%v; automatic Compose rollback failed: %w", reason, rbErr)
		}
		return reason
	}

	cmd := exec.Command("docker", composeArgs...)
	cmd.Dir = "/workspace"
	out, err := cmd.CombinedOutput()
	if len(out) > 0 {
		_, _ = os.Stdout.Write(out)
	}
	if err != nil {
		return rollbackCompose(fmt.Errorf("docker compose up failed: %w", err))
	}
	if selfUpdate {
		// A successful Compose CLI exit is not enough for self-update. The new
		// Agent must first be the requested image, running/healthy, and then be
		// reached by the paired Controller over mTLS. If either check fails, restore
		// both the original Compose source and previous Agent image automatically.
		if err := waitComposeServiceReady(project, service, image, 90*time.Second); err != nil {
			return rollbackCompose(err)
		}
		if requireControllerAck {
			if err := waitSelfUpdateAck(6 * time.Minute); err != nil {
				return rollbackCompose(err)
			}
		} else {
			if err := waitComposeControllerReady(project, service, image, 90*time.Second); err != nil {
				return rollbackCompose(err)
			}
		}
	}
	return nil
}

func CopyStream(dst string, src io.Reader) error {
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, src)
	return err
}
