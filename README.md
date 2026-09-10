# ZentContainer

<p align="center"><img src="assets/zentcontainer-logo.png" alt="ZentContainer logo" width="220"></p>

**Simple Docker management for one or multiple hosts.**

ZentContainer is an MIT-licensed Docker management UI by **ZentWorks** with a self-contained WebUI and no runtime CDN/frontend dependency.

## Features

- Manage containers, images, volumes and networks
- Create and edit standalone containers with advanced Docker options
- Import `docker run` commands into the container creation form
- Live host and container CPU, memory and network metrics
- Logs, terminal, processes, diagnostics and mounted-volume file access
- Organize containers in groups across one or multiple Docker hosts
- Manage Compose projects with editing, validation, `.env` support, logs and lifecycle controls
- Scheduled and manual image update checks
- Controlled container updates with automatic rollback on failure
- Project and volume backup/restore
- Private registry support
- Controller/Agent mode for securely managing remote Docker hosts
- Self-update for Controllers and paired Agents
- Scoped API keys
- Built-in API Explorer and OpenAPI specification
- German and English WebUI and documentation
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

ZentContainer can update the Controller and paired Agents directly from the WebUI. Compose-managed and standalone Docker installations are supported. Existing configuration is preserved during the update, and a failed replacement is rolled back automatically.

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
