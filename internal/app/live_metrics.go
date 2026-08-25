package app

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/ZentWorks/ZentContainer/internal/dockerx"
)

const (
	dockerStorageFreshFor  = 60 * time.Second
	containerStatsFreshFor = 4 * time.Second
	containerStatsWorkers  = 6
)

type dockerStorageSummary struct {
	Available  bool  `json:"available"`
	Used       int64 `json:"used"`
	Images     int64 `json:"images"`
	Containers int64 `json:"containers"`
	Volumes    int64 `json:"volumes"`
	BuildCache int64 `json:"build_cache"`
}

func dockerStorageSummaryFromRaw(raw json.RawMessage) dockerStorageSummary {
	var x map[string]any
	if json.Unmarshal(raw, &x) != nil {
		return dockerStorageSummary{}
	}
	images := int64(asFloat(x["LayersSize"]))
	if images <= 0 {
		images = sumDockerDFField(x, "Images", "Size")
	}
	containers := sumDockerDFField(x, "Containers", "SizeRw")
	volumes := sumVolumeUsage(x)
	buildCache := sumDockerDFField(x, "BuildCache", "Size")
	return dockerStorageSummary{
		Available:  true,
		Used:       maxInt64(0, images) + maxInt64(0, containers) + maxInt64(0, volumes) + maxInt64(0, buildCache),
		Images:     maxInt64(0, images),
		Containers: maxInt64(0, containers),
		Volumes:    maxInt64(0, volumes),
		BuildCache: maxInt64(0, buildCache),
	}
}

func sumDockerDFField(x map[string]any, key, field string) int64 {
	var n int64
	if rows, ok := x[key].([]any); ok {
		for _, row := range rows {
			m, _ := row.(map[string]any)
			n += int64(asFloat(m[field]))
		}
	}
	return n
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func (a *App) cachedDockerStorage(_ context.Context, d *dockerx.Client) dockerStorageSummary {
	now := time.Now()
	a.storageMu.Lock()
	cached := a.storageData
	age := now.Sub(a.storageAt)
	if !a.storageAt.IsZero() && age < dockerStorageFreshFor {
		a.storageMu.Unlock()
		return cached
	}
	if !a.storageRefreshing {
		a.storageRefreshing = true
		go a.refreshDockerStorage(d)
	}
	a.storageMu.Unlock()
	return cached
}

func (a *App) refreshDockerStorage(d *dockerx.Client) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	raw, err := d.SystemDF(ctx)
	a.storageMu.Lock()
	defer a.storageMu.Unlock()
	a.storageRefreshing = false
	a.storageAt = time.Now()
	if err != nil {
		a.storageData = dockerStorageSummary{}
		return
	}
	a.storageData = dockerStorageSummaryFromRaw(raw)
}

type containerStatsRow struct {
	CPUPercent  float64 `json:"cpu_percent"`
	MemoryBytes uint64  `json:"memory_bytes"`
	MemoryLimit uint64  `json:"memory_limit"`
}

type containerStatsBatchResponse struct {
	SampledAt  string                       `json:"sampled_at"`
	Containers map[string]containerStatsRow `json:"containers"`
	Partial    bool                         `json:"partial,omitempty"`
}

type dockerContainerStats struct {
	CPUStats struct {
		CPUUsage struct {
			TotalUsage  uint64   `json:"total_usage"`
			PercpuUsage []uint64 `json:"percpu_usage"`
		} `json:"cpu_usage"`
		SystemCPUUsage uint64 `json:"system_cpu_usage"`
		OnlineCPUs     uint64 `json:"online_cpus"`
	} `json:"cpu_stats"`
	PreCPUStats struct {
		CPUUsage struct {
			TotalUsage uint64 `json:"total_usage"`
		} `json:"cpu_usage"`
		SystemCPUUsage uint64 `json:"system_cpu_usage"`
	} `json:"precpu_stats"`
	MemoryStats struct {
		Usage uint64 `json:"usage"`
		Limit uint64 `json:"limit"`
	} `json:"memory_stats"`
}

type containerStatsCPUPoint struct {
	Total  uint64
	System uint64
	CPUs   uint64
}

func containerStatsRowFromRaw(raw json.RawMessage) (containerStatsRow, bool) {
	row, _, ok := containerStatsRowAndPoint(raw, nil)
	return row, ok
}

func containerStatsRowAndPoint(raw json.RawMessage, previous *containerStatsCPUPoint) (containerStatsRow, containerStatsCPUPoint, bool) {
	var s dockerContainerStats
	if json.Unmarshal(raw, &s) != nil {
		return containerStatsRow{}, containerStatsCPUPoint{}, false
	}
	cpus := s.CPUStats.OnlineCPUs
	if cpus == 0 {
		cpus = uint64(len(s.CPUStats.CPUUsage.PercpuUsage))
	}
	if cpus == 0 && previous != nil {
		cpus = previous.CPUs
	}
	if cpus == 0 {
		cpus = 1
	}
	point := containerStatsCPUPoint{Total: s.CPUStats.CPUUsage.TotalUsage, System: s.CPUStats.SystemCPUUsage, CPUs: cpus}
	baseTotal, baseSystem := s.PreCPUStats.CPUUsage.TotalUsage, s.PreCPUStats.SystemCPUUsage
	if (baseTotal == 0 || baseSystem == 0) && previous != nil {
		baseTotal, baseSystem = previous.Total, previous.System
	}
	cpuDelta, systemDelta := float64(0), float64(0)
	if point.Total >= baseTotal {
		cpuDelta = float64(point.Total - baseTotal)
	}
	if point.System >= baseSystem {
		systemDelta = float64(point.System - baseSystem)
	}
	cpu := float64(0)
	if baseSystem > 0 && cpuDelta > 0 && systemDelta > 0 {
		cpu = cpuDelta / systemDelta * float64(cpus) * 100
	}
	return containerStatsRow{CPUPercent: cpu, MemoryBytes: s.MemoryStats.Usage, MemoryLimit: s.MemoryStats.Limit}, point, true
}

func (a *App) containerStatsBatch(w http.ResponseWriter, r *http.Request) {
	d, err := a.docker()
	if err != nil {
		errorJSON(w, 503, "docker_unavailable", err.Error())
		return
	}

	a.containerStatsMu.Lock()
	cached := cloneContainerStatsBatch(a.containerStatsData)
	age := time.Since(a.containerStatsAt)
	refreshing := a.containerStatsRefreshing
	if !a.containerStatsAt.IsZero() && age < containerStatsFreshFor {
		a.containerStatsMu.Unlock()
		writeJSON(w, cached)
		return
	}
	if refreshing {
		a.containerStatsMu.Unlock()
		if !a.containerStatsAt.IsZero() {
			cached.Partial = true
			writeJSON(w, cached)
			return
		}
		// A first request is already collecting. Wait briefly rather than starting
		// an overlapping N-container sample.
		deadline := time.NewTimer(2 * time.Second)
		defer deadline.Stop()
		ticker := time.NewTicker(25 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case <-deadline.C:
				writeJSON(w, containerStatsBatchResponse{SampledAt: time.Now().UTC().Format(time.RFC3339Nano), Containers: map[string]containerStatsRow{}, Partial: true})
				return
			case <-ticker.C:
				a.containerStatsMu.Lock()
				ready := !a.containerStatsRefreshing
				result := cloneContainerStatsBatch(a.containerStatsData)
				a.containerStatsMu.Unlock()
				if ready {
					writeJSON(w, result)
					return
				}
			}
		}
	}
	a.containerStatsRefreshing = true
	a.containerStatsMu.Unlock()

	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	result, points := a.collectContainerStatsBatch(ctx, d)
	a.containerStatsMu.Lock()
	a.containerStatsData = cloneContainerStatsBatch(result)
	a.containerStatsAt = time.Now()
	a.containerStatsPrev = points
	a.containerStatsRefreshing = false
	a.containerStatsMu.Unlock()
	writeJSON(w, result)
}

func (a *App) collectContainerStatsBatch(ctx context.Context, d *dockerx.Client) (containerStatsBatchResponse, map[string]containerStatsCPUPoint) {
	result := containerStatsBatchResponse{SampledAt: time.Now().UTC().Format(time.RFC3339Nano), Containers: map[string]containerStatsRow{}}
	a.containerStatsMu.Lock()
	previous := make(map[string]containerStatsCPUPoint, len(a.containerStatsPrev))
	for id, point := range a.containerStatsPrev {
		previous[id] = point
	}
	a.containerStatsMu.Unlock()
	points := map[string]containerStatsCPUPoint{}
	containers, err := d.Containers(ctx, false)
	if err != nil {
		result.Partial = true
		return result, points
	}
	ids := make([]string, 0, len(containers))
	for _, c := range containers {
		if c.State == "running" && !isBackup(c) {
			ids = append(ids, c.ID)
		}
	}
	if len(ids) == 0 {
		return result, points
	}

	workers := containerStatsWorkers
	if workers > len(ids) {
		workers = len(ids)
	}
	jobs := make(chan string)
	var wg sync.WaitGroup
	var mu sync.Mutex
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for id := range jobs {
				if ctx.Err() != nil {
					return
				}
				raw, err := d.ContainerStats(ctx, id)
				if err != nil {
					mu.Lock()
					result.Partial = true
					mu.Unlock()
					continue
				}
				prev, hasPrev := previous[id]
				var prevPtr *containerStatsCPUPoint
				if hasPrev {
					prevPtr = &prev
				}
				row, point, ok := containerStatsRowAndPoint(raw, prevPtr)
				if !ok {
					mu.Lock()
					result.Partial = true
					mu.Unlock()
					continue
				}
				mu.Lock()
				result.Containers[id] = row
				points[id] = point
				mu.Unlock()
			}
		}()
	}
	for _, id := range ids {
		select {
		case <-ctx.Done():
			result.Partial = true
			close(jobs)
			wg.Wait()
			return result, points
		case jobs <- id:
		}
	}
	close(jobs)
	wg.Wait()
	return result, points
}

func cloneContainerStatsBatch(in containerStatsBatchResponse) containerStatsBatchResponse {
	out := in
	out.Containers = make(map[string]containerStatsRow, len(in.Containers))
	for k, v := range in.Containers {
		out.Containers[k] = v
	}
	return out
}
