package dockerx

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	Socket     string
	HTTP       *http.Client
	APIVersion string
}

type ContainerSummary struct {
	ID              string            `json:"Id"`
	Names           []string          `json:"Names"`
	Image           string            `json:"Image"`
	ImageID         string            `json:"ImageID"`
	Command         string            `json:"Command"`
	Created         int64             `json:"Created"`
	State           string            `json:"State"`
	Status          string            `json:"Status"`
	Ports           []Port            `json:"Ports"`
	Labels          map[string]string `json:"Labels"`
	NetworkSettings struct {
		Networks map[string]Endpoint `json:"Networks"`
	} `json:"NetworkSettings"`
	Mounts []Mount `json:"Mounts"`
}
type Port struct {
	IP          string `json:"IP"`
	PrivatePort int    `json:"PrivatePort"`
	PublicPort  int    `json:"PublicPort"`
	Type        string `json:"Type"`
}
type Endpoint struct {
	IPAddress string `json:"IPAddress"`
	Gateway   string `json:"Gateway"`
	NetworkID string `json:"NetworkID"`
}
type Mount struct {
	Type        string `json:"Type"`
	Name        string `json:"Name"`
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	Driver      string `json:"Driver"`
	Mode        string `json:"Mode"`
	RW          bool   `json:"RW"`
}
type ImageSummary struct {
	Containers  int64             `json:"Containers"`
	Created     int64             `json:"Created"`
	ID          string            `json:"Id"`
	Labels      map[string]string `json:"Labels"`
	ParentID    string            `json:"ParentId"`
	RepoDigests []string          `json:"RepoDigests"`
	RepoTags    []string          `json:"RepoTags"`
	SharedSize  int64             `json:"SharedSize"`
	Size        int64             `json:"Size"`
}
type Volume struct {
	CreatedAt  string            `json:"CreatedAt"`
	Driver     string            `json:"Driver"`
	Labels     map[string]string `json:"Labels"`
	Mountpoint string            `json:"Mountpoint"`
	Name       string            `json:"Name"`
	Options    map[string]string `json:"Options"`
	Scope      string            `json:"Scope"`
}
type VolumeUsage struct {
	Name      string `json:"Name"`
	UsageData struct {
		Size     int64 `json:"Size"`
		RefCount int64 `json:"RefCount"`
	} `json:"UsageData"`
}
type NetworkContainer struct {
	Name        string `json:"Name"`
	EndpointID  string `json:"EndpointID"`
	MacAddress  string `json:"MacAddress"`
	IPv4Address string `json:"IPv4Address"`
	IPv6Address string `json:"IPv6Address"`
}

type Network struct {
	Name       string `json:"Name"`
	ID         string `json:"Id"`
	Created    string `json:"Created"`
	Scope      string `json:"Scope"`
	Driver     string `json:"Driver"`
	EnableIPv6 bool   `json:"EnableIPv6"`
	Internal   bool   `json:"Internal"`
	Attachable bool   `json:"Attachable"`
	Ingress    bool   `json:"Ingress"`
	IPAM       struct {
		Driver string                                        `json:"Driver"`
		Config []struct{ Subnet, IPAddress, Gateway string } `json:"Config"`
	} `json:"IPAM"`
	Containers map[string]NetworkContainer `json:"Containers"`
}

type CreateContainerRequest struct {
	Image            string                    `json:"Image"`
	Cmd              []string                  `json:"Cmd,omitempty"`
	Entrypoint       []string                  `json:"Entrypoint,omitempty"`
	MacAddress       string                    `json:"MacAddress,omitempty"`
	Env              []string                  `json:"Env,omitempty"`
	WorkingDir       string                    `json:"WorkingDir,omitempty"`
	Hostname         string                    `json:"Hostname,omitempty"`
	User             string                    `json:"User,omitempty"`
	Labels           map[string]string         `json:"Labels,omitempty"`
	ExposedPorts     map[string]map[string]any `json:"ExposedPorts,omitempty"`
	Healthcheck      *HealthConfig             `json:"Healthcheck,omitempty"`
	HostConfig       HostConfig                `json:"HostConfig"`
	NetworkingConfig *NetworkingConfig         `json:"NetworkingConfig,omitempty"`
}
type HealthConfig struct {
	Test        []string `json:"Test,omitempty"`
	Interval    int64    `json:"Interval,omitempty"`
	Timeout     int64    `json:"Timeout,omitempty"`
	Retries     int      `json:"Retries,omitempty"`
	StartPeriod int64    `json:"StartPeriod,omitempty"`
}
type HostConfig struct {
	Binds             []string                 `json:"Binds,omitempty"`
	PortBindings      map[string][]PortBinding `json:"PortBindings,omitempty"`
	RestartPolicy     RestartPolicy            `json:"RestartPolicy,omitempty"`
	NetworkMode       string                   `json:"NetworkMode,omitempty"`
	ReadonlyRootfs    bool                     `json:"ReadonlyRootfs,omitempty"`
	Privileged        bool                     `json:"Privileged,omitempty"`
	CapAdd            []string                 `json:"CapAdd,omitempty"`
	CapDrop           []string                 `json:"CapDrop,omitempty"`
	SecurityOpt       []string                 `json:"SecurityOpt,omitempty"`
	AutoRemove        bool                     `json:"AutoRemove,omitempty"`
	Memory            int64                    `json:"Memory,omitempty"`
	MemoryReservation int64                    `json:"MemoryReservation,omitempty"`
	MemorySwap        int64                    `json:"MemorySwap,omitempty"`
	NanoCPUs          int64                    `json:"NanoCpus,omitempty"`
	CpuShares         int64                    `json:"CpuShares,omitempty"`
	CpuPeriod         int64                    `json:"CpuPeriod,omitempty"`
	CpuQuota          int64                    `json:"CpuQuota,omitempty"`
	CpusetCpus        string                   `json:"CpusetCpus,omitempty"`
	PidsLimit         int64                    `json:"PidsLimit,omitempty"`
	Dns               []string                 `json:"Dns,omitempty"`
	DnsSearch         []string                 `json:"DnsSearch,omitempty"`
	ExtraHosts        []string                 `json:"ExtraHosts,omitempty"`
	Devices           []DeviceMapping          `json:"Devices,omitempty"`
	DeviceRequests    []DeviceRequest          `json:"DeviceRequests,omitempty"`
}
type DeviceMapping struct {
	PathOnHost        string `json:"PathOnHost"`
	PathInContainer   string `json:"PathInContainer"`
	CgroupPermissions string `json:"CgroupPermissions"`
}
type DeviceRequest struct {
	Driver       string            `json:"Driver,omitempty"`
	Count        int               `json:"Count,omitempty"`
	DeviceIDs    []string          `json:"DeviceIDs,omitempty"`
	Capabilities [][]string        `json:"Capabilities,omitempty"`
	Options      map[string]string `json:"Options,omitempty"`
}
type NetworkingConfig struct {
	EndpointsConfig map[string]EndpointSettings `json:"EndpointsConfig"`
}
type EndpointSettings struct {
	IPAMConfig *EndpointIPAMConfig `json:"IPAMConfig,omitempty"`
	Links      []string            `json:"Links,omitempty"`
	Aliases    []string            `json:"Aliases,omitempty"`
	MacAddress string              `json:"MacAddress,omitempty"`
	DriverOpts map[string]string   `json:"DriverOpts,omitempty"`
	GwPriority int                 `json:"GwPriority,omitempty"`
}
type EndpointIPAMConfig struct {
	IPv4Address  string   `json:"IPv4Address,omitempty"`
	IPv6Address  string   `json:"IPv6Address,omitempty"`
	LinkLocalIPs []string `json:"LinkLocalIPs,omitempty"`
}
type PortBinding struct {
	HostIP   string `json:"HostIp,omitempty"`
	HostPort string `json:"HostPort"`
}
type RestartPolicy struct {
	Name              string `json:"Name"`
	MaximumRetryCount int    `json:"MaximumRetryCount,omitempty"`
}

func New(socket string) (*Client, error) {
	tr := &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", socket)
	}}
	c := &Client{Socket: socket, HTTP: &http.Client{Transport: tr}}
	var v struct {
		APIVersion string `json:"ApiVersion"`
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := c.raw(ctx, http.MethodGet, "/version", nil, &v, false); err != nil {
		return nil, err
	}
	if v.APIVersion == "" {
		return nil, errors.New("docker daemon returned no API version")
	}
	c.APIVersion = v.APIVersion
	return c, nil
}
func (c *Client) prefix(path string) string { return "/v" + c.APIVersion + path }
func (c *Client) raw(ctx context.Context, method, path string, body any, out any, versioned bool) ([]byte, error) {
	return c.rawHeaders(ctx, method, path, body, out, versioned, nil)
}
func (c *Client) rawHeaders(ctx context.Context, method, path string, body any, out any, versioned bool, headers map[string]string) ([]byte, error) {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		r = bytes.NewReader(b)
	}
	if versioned {
		path = c.prefix(path)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://docker"+path, r)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		if v != "" {
			req.Header.Set(k, v)
		}
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("docker %s %s: HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return nil, fmt.Errorf("decode docker response: %w", err)
		}
	}
	return data, nil
}
func (c *Client) GetRaw(ctx context.Context, path string) (json.RawMessage, error) {
	b, err := c.raw(ctx, http.MethodGet, path, nil, nil, true)
	return json.RawMessage(b), err
}
func (c *Client) Info(ctx context.Context) (json.RawMessage, error) { return c.GetRaw(ctx, "/info") }
func (c *Client) SystemDF(ctx context.Context) (json.RawMessage, error) {
	return c.GetRaw(ctx, "/system/df")
}
func (c *Client) Containers(ctx context.Context, all bool) ([]ContainerSummary, error) {
	out := []ContainerSummary{}
	_, err := c.raw(ctx, http.MethodGet, "/containers/json?all="+strconv.FormatBool(all), nil, &out, true)
	return out, err
}
func (c *Client) ContainerInspect(ctx context.Context, id string) (json.RawMessage, error) {
	return c.GetRaw(ctx, "/containers/"+url.PathEscape(id)+"/json")
}
func (c *Client) ContainerAction(ctx context.Context, id, action string) error {
	path := "/containers/" + url.PathEscape(id) + "/" + action
	if action == "stop" || action == "restart" {
		path += "?t=10"
	}
	_, err := c.raw(ctx, http.MethodPost, path, map[string]any{}, nil, true)
	return err
}
func (c *Client) ContainerRemove(ctx context.Context, id string, force bool) error {
	_, err := c.raw(ctx, http.MethodDelete, "/containers/"+url.PathEscape(id)+"?force="+strconv.FormatBool(force), nil, nil, true)
	return err
}
func (c *Client) ContainerCreate(ctx context.Context, name string, req CreateContainerRequest) (string, error) {
	var out struct {
		ID       string   `json:"Id"`
		Warnings []string `json:"Warnings"`
	}
	_, err := c.raw(ctx, http.MethodPost, "/containers/create?name="+url.QueryEscape(name), req, &out, true)
	return out.ID, err
}
func (c *Client) ContainerLogs(ctx context.Context, id string, tail int) ([]byte, error) {
	return c.ContainerOutput(ctx, id, tail, true)
}

// ContainerOutput reads a container's stdout/stderr. Helpers use timestamps=false so
// machine-readable JSON is not prefixed with Docker log timestamps.
func (c *Client) ContainerOutput(ctx context.Context, id string, tail int, timestamps bool) ([]byte, error) {
	if tail <= 0 {
		tail = 200
	}
	path := "/containers/" + url.PathEscape(id) + "/logs?stdout=1&stderr=1&timestamps=" + strconv.FormatBool(timestamps) + "&tail=" + strconv.Itoa(tail)
	b, err := c.raw(ctx, http.MethodGet, path, nil, nil, true)
	if err != nil {
		return nil, err
	}
	return demuxDocker(b), nil
}
func demuxDocker(b []byte) []byte {
	if len(b) < 8 {
		return b
	}
	var out bytes.Buffer
	for len(b) >= 8 {
		size := int(b[4])<<24 | int(b[5])<<16 | int(b[6])<<8 | int(b[7])
		if size < 0 || size > len(b)-8 {
			return b
		}
		out.Write(b[8 : 8+size])
		b = b[8+size:]
	}
	return out.Bytes()
}
func (c *Client) ContainerStats(ctx context.Context, id string) (json.RawMessage, error) {
	return c.GetRaw(ctx, "/containers/"+url.PathEscape(id)+"/stats?stream=false&one-shot=true")
}

func (c *Client) ContainerTop(ctx context.Context, id string) (json.RawMessage, error) {
	return c.GetRaw(ctx, "/containers/"+url.PathEscape(id)+"/top?ps_args="+url.QueryEscape("-eo pid,user,pcpu,pmem,etime,args"))
}

func (c *Client) ContainerArchive(ctx context.Context, id, path string) ([]byte, error) {
	return c.RawBytes(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/archive?path="+url.QueryEscape(path), "", nil)
}

func (c *Client) ContainerArchivePut(ctx context.Context, id, path string, tarData []byte) error {
	_, err := c.RawBytes(ctx, http.MethodPut, "/containers/"+url.PathEscape(id)+"/archive?path="+url.QueryEscape(path), "application/x-tar", bytes.NewReader(tarData))
	return err
}
func (c *Client) Images(ctx context.Context) ([]ImageSummary, error) {
	out := []ImageSummary{}
	_, err := c.raw(ctx, http.MethodGet, "/images/json?all=0", nil, &out, true)
	return out, err
}
func (c *Client) ImageInspect(ctx context.Context, id string) (json.RawMessage, error) {
	return c.GetRaw(ctx, "/images/"+url.PathEscape(id)+"/json")
}
func (c *Client) ImageHistory(ctx context.Context, id string) (json.RawMessage, error) {
	return c.GetRaw(ctx, "/images/"+url.PathEscape(id)+"/history")
}
func (c *Client) ImageRemove(ctx context.Context, id string, force bool) error {
	_, err := c.raw(ctx, http.MethodDelete, "/images/"+url.PathEscape(id)+"?force="+strconv.FormatBool(force), nil, nil, true)
	return err
}
func RegistryAuth(username, password, server string) (string, error) {
	if strings.EqualFold(strings.TrimSpace(server), "docker.io") {
		server = "https://index.docker.io/v1/"
	}
	b, err := json.Marshal(map[string]string{"username": username, "password": password, "serveraddress": server})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func (c *Client) ImagePull(ctx context.Context, ref string) ([]byte, error) {
	return c.ImagePullAuth(ctx, ref, "")
}
func (c *Client) ImagePullAuth(ctx context.Context, ref, registryAuth string) ([]byte, error) {
	from, tag := splitImageRef(ref)
	path := "/images/create?fromImage=" + url.QueryEscape(from)
	if tag != "" {
		path += "&tag=" + url.QueryEscape(tag)
	}
	headers := map[string]string{}
	if registryAuth != "" {
		headers["X-Registry-Auth"] = registryAuth
	}
	return c.rawHeaders(ctx, http.MethodPost, path, nil, nil, true, headers)
}

// ImagePullProgress streams Docker pull events while the image is downloaded.
// The callback is invoked for every JSON progress record returned by Docker.
type ImagePullProgressEvent struct {
	Status         string `json:"status"`
	ID             string `json:"id"`
	Progress       string `json:"progress"`
	Error          string `json:"error"`
	ProgressDetail struct {
		Current int64 `json:"current"`
		Total   int64 `json:"total"`
	} `json:"progressDetail"`
}

func (c *Client) ImagePullProgress(ctx context.Context, ref, registryAuth string, fn func(ImagePullProgressEvent)) error {
	from, tag := splitImageRef(ref)
	path := "/images/create?fromImage=" + url.QueryEscape(from)
	if tag != "" {
		path += "&tag=" + url.QueryEscape(tag)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://docker"+c.prefix(path), nil)
	if err != nil {
		return err
	}
	if registryAuth != "" {
		req.Header.Set("X-Registry-Auth", registryAuth)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("docker POST %s: HTTP %d: %s", c.prefix(path), resp.StatusCode, strings.TrimSpace(string(b)))
	}
	dec := json.NewDecoder(resp.Body)
	for {
		var ev ImagePullProgressEvent
		if err := dec.Decode(&ev); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("decode docker pull progress: %w", err)
		}
		if fn != nil {
			fn(ev)
		}
		if strings.TrimSpace(ev.Error) != "" {
			return errors.New(ev.Error)
		}
	}
}

func splitImageRef(ref string) (string, string) {
	if strings.Contains(ref, "@sha256:") {
		return ref, ""
	}
	slash := strings.LastIndex(ref, "/")
	colon := strings.LastIndex(ref, ":")
	if colon > slash {
		return ref[:colon], ref[colon+1:]
	}
	return ref, "latest"
}
func (c *Client) DistributionInspect(ctx context.Context, ref string) (json.RawMessage, error) {
	return c.DistributionInspectAuth(ctx, ref, "")
}
func (c *Client) DistributionInspectAuth(ctx context.Context, ref, registryAuth string) (json.RawMessage, error) {
	headers := map[string]string{}
	if registryAuth != "" {
		headers["X-Registry-Auth"] = registryAuth
	}
	b, err := c.rawHeaders(ctx, http.MethodGet, "/distribution/"+url.PathEscape(ref)+"/json", nil, nil, true, headers)
	return json.RawMessage(b), err
}
func (c *Client) Volumes(ctx context.Context) ([]Volume, error) {
	var out struct {
		Volumes []Volume `json:"Volumes"`
	}
	_, err := c.raw(ctx, http.MethodGet, "/volumes", nil, &out, true)
	if out.Volumes == nil {
		out.Volumes = []Volume{}
	}
	return out.Volumes, err
}

func (c *Client) VolumeDiskUsage(ctx context.Context) (map[string]int64, error) {
	var out struct {
		Volumes []VolumeUsage `json:"Volumes"`
	}
	_, err := c.raw(ctx, http.MethodGet, "/system/df?type=volume", nil, &out, true)
	if err != nil {
		return nil, err
	}
	m := map[string]int64{}
	for _, v := range out.Volumes {
		if v.UsageData.Size >= 0 {
			m[v.Name] = v.UsageData.Size
		}
	}
	return m, nil
}
func (c *Client) VolumeInspect(ctx context.Context, name string) (json.RawMessage, error) {
	return c.GetRaw(ctx, "/volumes/"+url.PathEscape(name))
}
func (c *Client) VolumeCreate(ctx context.Context, name, driver string) (Volume, error) {
	if driver == "" {
		driver = "local"
	}
	var out Volume
	_, err := c.raw(ctx, http.MethodPost, "/volumes/create", map[string]any{"Name": name, "Driver": driver}, &out, true)
	return out, err
}
func (c *Client) VolumeRemove(ctx context.Context, name string, force bool) error {
	_, err := c.raw(ctx, http.MethodDelete, "/volumes/"+url.PathEscape(name)+"?force="+strconv.FormatBool(force), nil, nil, true)
	return err
}
func (c *Client) Networks(ctx context.Context) ([]Network, error) {
	out := []Network{}
	_, err := c.raw(ctx, http.MethodGet, "/networks", nil, &out, true)
	return out, err
}
func (c *Client) NetworkInspect(ctx context.Context, id string) (json.RawMessage, error) {
	return c.GetRaw(ctx, "/networks/"+url.PathEscape(id))
}
func (c *Client) NetworkCreate(ctx context.Context, name, driver, subnet, gateway string) (string, error) {
	return c.NetworkCreateAdvanced(ctx, NetworkCreateRequest{Name: name, Driver: driver, Subnet: subnet, Gateway: gateway})
}

type NetworkCreateRequest struct {
	Name       string
	Driver     string
	Subnet     string
	Gateway    string
	Parent     string
	EnableIPv6 bool
	Internal   bool
	Attachable bool
}

func (c *Client) NetworkCreateAdvanced(ctx context.Context, in NetworkCreateRequest) (string, error) {
	body := map[string]any{"Name": in.Name, "Driver": in.Driver, "EnableIPv6": in.EnableIPv6, "Internal": in.Internal, "Attachable": in.Attachable}
	if in.Subnet != "" || in.Gateway != "" {
		cfg := map[string]string{}
		if in.Subnet != "" {
			cfg["Subnet"] = in.Subnet
		}
		if in.Gateway != "" {
			cfg["Gateway"] = in.Gateway
		}
		body["IPAM"] = map[string]any{"Config": []any{cfg}}
	}
	if in.Parent != "" {
		body["Options"] = map[string]string{"parent": in.Parent}
	}
	var out struct {
		ID string `json:"Id"`
	}
	_, err := c.raw(ctx, http.MethodPost, "/networks/create", body, &out, true)
	return out.ID, err
}
func (c *Client) NetworkRemove(ctx context.Context, id string) error {
	_, err := c.raw(ctx, http.MethodDelete, "/networks/"+url.PathEscape(id), nil, nil, true)
	return err
}
func (c *Client) NetworkConnect(ctx context.Context, id, container string) error {
	_, err := c.raw(ctx, http.MethodPost, "/networks/"+url.PathEscape(id)+"/connect", map[string]any{"Container": container}, nil, true)
	return err
}
func (c *Client) NetworkDisconnect(ctx context.Context, id, container string, force bool) error {
	_, err := c.raw(ctx, http.MethodPost, "/networks/"+url.PathEscape(id)+"/disconnect", map[string]any{"Container": container, "Force": force}, nil, true)
	return err
}

func (c *Client) ExecRun(ctx context.Context, container string, cmd []string) ([]byte, error) {
	var out struct {
		ID string `json:"Id"`
	}
	body := map[string]any{"AttachStdout": true, "AttachStderr": true, "Tty": false, "Cmd": cmd}
	if _, err := c.raw(ctx, http.MethodPost, "/containers/"+url.PathEscape(container)+"/exec", body, &out, true); err != nil {
		return nil, err
	}
	b, err := c.raw(ctx, http.MethodPost, "/exec/"+url.PathEscape(out.ID)+"/start", map[string]any{"Detach": false, "Tty": false}, nil, true)
	if err != nil {
		return nil, err
	}
	return demuxDocker(b), nil
}

func (c *Client) ExecCreate(ctx context.Context, container string, cmd []string) (string, error) {
	var out struct {
		ID string `json:"Id"`
	}
	body := map[string]any{"AttachStdin": true, "AttachStdout": true, "AttachStderr": true, "Tty": true, "Cmd": cmd}
	_, err := c.raw(ctx, http.MethodPost, "/containers/"+url.PathEscape(container)+"/exec", body, &out, true)
	return out.ID, err
}
func (c *Client) ExecResize(ctx context.Context, execID string, h, w int) error {
	_, err := c.raw(ctx, http.MethodPost, "/exec/"+url.PathEscape(execID)+"/resize?h="+strconv.Itoa(h)+"&w="+strconv.Itoa(w), map[string]any{}, nil, true)
	return err
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }
func (c *Client) ExecAttach(ctx context.Context, execID string) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", c.Socket)
	if err != nil {
		return nil, err
	}
	body := `{"Detach":false,"Tty":true}`
	path := c.prefix("/exec/" + url.PathEscape(execID) + "/start")
	req := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Length: %d\r\n\r\n%s", path, len(body), body)
	if _, err := io.WriteString(conn, req); err != nil {
		conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp.StatusCode != 101 && resp.StatusCode != 200 {
		data, _ := io.ReadAll(resp.Body)
		conn.Close()
		return nil, fmt.Errorf("docker exec attach: HTTP %d: %s", resp.StatusCode, string(data))
	}
	return &bufferedConn{Conn: conn, r: br}, nil
}

func (c *Client) ContainerRename(ctx context.Context, id, name string) error {
	_, err := c.raw(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/rename?name="+url.QueryEscape(name), map[string]any{}, nil, true)
	return err
}
func (c *Client) ContainerWait(ctx context.Context, id string) error {
	var out map[string]any
	_, err := c.raw(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/wait?condition=not-running", map[string]any{}, &out, true)
	return err
}
func (c *Client) ContainerCreateMap(ctx context.Context, name string, body map[string]any) (string, error) {
	var out struct {
		ID string `json:"Id"`
	}
	_, err := c.raw(ctx, http.MethodPost, "/containers/create?name="+url.QueryEscape(name), body, &out, true)
	return out.ID, err
}
func (c *Client) Call(ctx context.Context, method, path string, body any) (json.RawMessage, error) {
	b, err := c.raw(ctx, method, path, body, nil, true)
	return json.RawMessage(b), err
}
func (c *Client) RawBytes(ctx context.Context, method, path, contentType string, body io.Reader) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, "http://docker"+c.prefix(path), body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("docker %s %s: HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return data, nil
}

func (c *Client) NetworkConnectConfig(ctx context.Context, id, container string, endpoint map[string]any) error {
	body := map[string]any{"Container": container}
	if endpoint != nil {
		body["EndpointConfig"] = endpoint
	}
	_, err := c.raw(ctx, http.MethodPost, "/networks/"+url.PathEscape(id)+"/connect", body, nil, true)
	return err
}

func (c *Client) RecentEvents(ctx context.Context, since, until int64) ([]json.RawMessage, error) {
	path := "/events?since=" + strconv.FormatInt(since, 10) + "&until=" + strconv.FormatInt(until, 10)
	b, err := c.raw(ctx, http.MethodGet, path, nil, nil, true)
	if err != nil {
		return nil, err
	}
	out := []json.RawMessage{}
	for _, line := range bytes.Split(b, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		if json.Valid(line) {
			out = append(out, append(json.RawMessage(nil), line...))
		}
	}
	return out, nil
}
