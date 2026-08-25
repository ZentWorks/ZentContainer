# Security Policy

ZentContainer controls Docker through the host Docker socket. Treat access to ZentContainer as host-administrator access.

## Deployment guidance

- Run ZentContainer only on trusted management networks or behind a trusted VPN/reverse proxy.
- Use HTTPS for the Controller WebUI and set `ZC_COOKIE_SECURE=true` when HTTPS is used exclusively.
- Restrict Agent TCP port `9444` to the Controller or management network where possible.
- Protect and back up the ZentContainer data directory as sensitive administrative data.
- Rotate API keys when they are no longer needed.

## Reporting a vulnerability

Please use GitHub Private Vulnerability Reporting for the ZentWorks/ZentContainer repository instead of opening a public issue for security-sensitive reports.
