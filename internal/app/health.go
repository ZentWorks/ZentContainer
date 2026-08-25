package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ZentWorks/ZentContainer/internal/dockerx"
)

func waitContainerHealthy(ctx context.Context, d *dockerx.Client, id string, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	deadline := time.Now().Add(timeout)
	for {
		raw, err := d.ContainerInspect(ctx, id)
		if err != nil {
			return err
		}
		var v struct {
			State struct {
				Running bool   `json:"Running"`
				Status  string `json:"Status"`
				Health  *struct {
					Status string `json:"Status"`
				} `json:"Health"`
			} `json:"State"`
		}
		if err := json.Unmarshal(raw, &v); err != nil {
			return err
		}
		if !v.State.Running {
			return fmt.Errorf("replacement is not running (state: %s)", v.State.Status)
		}
		if v.State.Health == nil {
			// Without a Docker healthcheck we can only verify that the process remains running.
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(2 * time.Second):
			}
			raw2, err := d.ContainerInspect(ctx, id)
			if err != nil {
				return err
			}
			var v2 struct {
				State struct {
					Running bool `json:"Running"`
				} `json:"State"`
			}
			if json.Unmarshal(raw2, &v2) != nil || !v2.State.Running {
				return errors.New("replacement stopped shortly after start")
			}
			return nil
		}
		switch v.State.Health.Status {
		case "healthy":
			return nil
		case "unhealthy":
			return errors.New("replacement reported unhealthy")
		}
		if time.Now().After(deadline) {
			return errors.New("healthcheck did not become healthy before timeout")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}
