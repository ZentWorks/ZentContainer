# ZentContainer

<p align="center"><img src="assets/zentcontainer-logo.png" alt="ZentContainer logo" width="220"></p>

**Simple Docker management for one or multiple hosts.**

ZentContainer is an MIT-licensed Docker management UI by **ZentWorks** with a self-contained WebUI and no runtime CDN/frontend dependency.

## Features

- Manage containers, images, volumes and networks
- Preserve per-network IP/MAC identity during standalone container edits, updates and rollback
- Clear primary/additional network selection in the container form; `host` and `none` stay exclusive and do not expose irrelevant identity fields
- Create and edit standalone containers, including editable Host-IP-specific port bindings and safe `docker run` command import that fills the structured form without executing shell input; supported values are applied explicitly, including environment variables, ports, mounts, TTY/STDIN/init and advanced Docker settings
- Live host and container CPU/RAM/network throughput metrics with host CPU sampled across the normal live interval and VPS steal/I/O-wait reported separately
- Logs, terminal, processes, diagnostics and mounted-volume file access
- Container groups across one or multiple Docker hosts with aggregated live CPU/RAM/network throughput, member-level update highlighting inside groups and direct cleanup of members whose containers no longer exist
- Compose project management with editing, validation, logs and lifecycle controls, a clickable `.env` variable assistant, and lowercase filesystem-safe project-name normalization enforced in both WebUI and API
- Scheduled and manual image update checks with persistent update markers and contextual update buttons only when an update is confirmed, plus controlled container updates with live step-by-step progress, automatic rollback on failure and automatic removal of temporary rollback/update-helper containers after completion
- Project and volume backup/restore
- Private registry credentials stored encrypted
- Controller/Agent mode for remote Docker hosts using TLS 1.3 + mTLS
- Self-update for the Controller and paired Agents, including Compose and standalone Docker installations
- Scoped API keys
- Built-in API Explorer and OpenAPI specification
- German and English WebUI/documentation
- Responsive installable Web App for desktop and mobile browsers

## Installation

### Docker Compose

Create `compose.yaml`:

```yaml
services:
  zentcontainer:
    image: ghcr.io/zentworks/zentcontainer:latest
    container_name: zentcontainer
    restart: unless-stopped
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    ports:
      - "9443:9443"
      - "9444:9444"
    environment:
      ZC_DATA_DIR: /opt/zentcontainer
      ZC_COOKIE_SECURE: "false"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /proc:/host-proc:ro
      - /etc/hostname:/host-hostname:ro
      - /etc/os-release:/host-os-release:ro
      - /opt/zentcontainer:/opt/zentcontainer
```

Start it:

```bash
docker compose up -d
```

### Docker run

```bash
docker run -d \
  --name zentcontainer \
  --restart unless-stopped \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  -p 9443:9443 \
  -p 9444:9444 \
  -e ZC_DATA_DIR=/opt/zentcontainer \
  -e ZC_COOKIE_SECURE=false \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /proc:/host-proc:ro \
  -v /etc/hostname:/host-hostname:ro \
  -v /etc/os-release:/host-os-release:ro \
  -v /opt/zentcontainer:/opt/zentcontainer \
  ghcr.io/zentworks/zentcontainer:latest
```

Open:

```text
http://YOUR-DOCKER-HOST:9443
```

Read the local first-run access code from the container logs:

```bash
docker logs zentcontainer
```

Enter the `ZCL1-...` code in the WebUI and choose **Controller** or **Agent**.

> If you use another persistent data path, keep the host and container path identical so Compose bind mounts resolve correctly from the Docker daemon.

## Install as a Web App

ZentContainer can be installed from supported browsers and opens in its own app window. Chrome/Edge on desktop and Android can offer the install action directly; Safari on iPhone/iPad uses **Share → Add to Home Screen**.

For full PWA installation and service-worker support, serve ZentContainer from a secure HTTPS origin (or localhost). Live API/session responses are never cached.

## Controller and Agent

A **Controller** manages its local Docker Engine and provides the full WebUI and REST API.

An **Agent** lets a Controller manage another Docker host. The Controller must be able to reach the Agent on TCP `9444`. Pairing uses a one-time code, certificate pinning, TLS 1.3 and mutual TLS.

ZentContainer can update itself and paired Agents directly from the WebUI. The active Controller/Agent container can also be checked and updated directly from the **Containers** detail action bar; ZentContainer automatically routes that exact self container to the safe self-update path. For same-reference updates such as `:latest` to a newer `:latest` digest, Compose-managed instances use exact Docker-inspect recreation instead of re-running Compose with potentially different client-side environment variables. The running mounts, environment, ports, labels and network identity are preserved while the Compose image reference remains unchanged. Changing to a different image reference still requires reachable editable Compose source. Docker-run, Unraid, Portainer and other Docker-created installations use the same exact recreation path. Failures roll back automatically, paired Agents additionally require the Controller to reconnect over mTLS, and the Controller must prove access to the previous persistent SQLite database before its update is committed.

## API

- API Explorer: `/api-docs`
- OpenAPI YAML: `/api/v1/openapi`
- REST API: `/api/v1/...`

For scripts, create a scoped API key under **API** and use it as a Bearer token:

```bash
curl -sS \
  -H "Authorization: Bearer zc_live_YOUR_API_KEY" \
  "http://YOUR-DOCKER-HOST:9443/api/v1/containers"
```

## Security

ZentContainer mounts `/var/run/docker.sock`, which gives it highly privileged control over the Docker host. Treat access to ZentContainer as host-administrator access.

The default deployment drops Linux capabilities and enables `no-new-privileges`. Host metrics use read-only `/proc`, hostname and OS-release mounts; the full host root is not mounted.

When serving ZentContainer through HTTPS, set:

```text
ZC_COOKIE_SECURE=true
```

See [SECURITY.md](SECURITY.md) for deployment guidance and vulnerability reporting.

## License

MIT — see [LICENSE](LICENSE).
