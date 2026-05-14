# Architecture

## Current Version

Version 3 runs as a FastAPI app with a SQLite database:

```text
Browser
  -> FastAPI static route
  -> index.html
  -> assets/styles.css
  -> assets/app.js
  -> /api/*
  -> SQLite database
  -> optional read-only TCP probes when lab mode is enabled
```

The frontend no longer writes operational data to `localStorage`. It only stores the selected demo role. Firewall rules, VPN tunnels, health checks, lab targets, and audit events are persisted by the backend in `data/ops_portal.sqlite3`.

## Backend

The backend lives in `backend/main.py`.

It provides:

- SQLite schema creation and demo seed data
- CRUD-style API endpoints for firewall rules and VPN tunnels
- approval and deployment transitions
- simulated health check execution
- OPNsense and pfSense snippet generation
- gated read-only TCP lab probes
- audit logging
- role checks using the `X-User-Role` request header

## Roles

The API accepts three roles:

```text
requester
approver
operator
```

Role boundaries:

- `requester` can create firewall rule requests and VPN entries.
- `approver` can approve or reject pending firewall and VPN requests.
- `operator` can deploy approved firewall rules, mark VPN tunnels up or down, run checks, manage lab targets, generate snippets, and reset demo data.

This is a portfolio simulation, not production authentication. A real deployment would replace the role header with proper identity, sessions, policy enforcement, and audit attribution.

## Main Data Objects

### Firewall Rule

```json
{
  "id": "FW-1001",
  "source": "10.10.10.0/24",
  "destination": "10.10.20.10",
  "protocol": "TCP",
  "port": "443",
  "reason": "User access to internal web application",
  "owner": "network.ops",
  "status": "pending",
  "risk": "low",
  "createdAt": "2026-05-14 09:00"
}
```

### VPN Tunnel

```json
{
  "id": "VPN-2001",
  "name": "HQ-BRANCH-IPSEC",
  "type": "IPsec",
  "peer": "198.51.100.20",
  "localNet": "10.10.20.0/24",
  "remoteNet": "10.20.10.0/24",
  "owner": "network.ops",
  "status": "up",
  "lastCheck": "2026-05-14 09:15"
}
```

### Health Check

```json
{
  "id": "CHK-1",
  "name": "HQ web app HTTPS",
  "target": "10.10.20.10:443",
  "type": "HTTPS",
  "status": "ok",
  "detail": "TLS handshake and HTTP response completed",
  "latency": 34,
  "lastRun": "2026-05-14 09:18"
}
```

### Lab Target

```json
{
  "id": "LAB-3001",
  "name": "OPNsense lab UI",
  "kind": "tcp",
  "host": "192.0.2.10",
  "port": 443,
  "enabled": true,
  "lastStatus": "skipped",
  "lastDetail": "Set OPS_PORTAL_LAB_MODE=enabled to contact configured lab hosts.",
  "lastRun": "2026-05-14 10:30"
}
```

## Controlled Lab Mode

Real lab checks are disabled by default. `POST /api/lab-checks/run` updates enabled targets as `skipped` unless the backend process was started with:

```powershell
$env:OPS_PORTAL_LAB_MODE = "enabled"
python -m uvicorn backend.main:app --reload
```

When enabled, the backend only attempts TCP connections to configured targets. It does not authenticate, execute commands, import configuration, or change firewall state.

## Snippet Generation

`GET /api/snippets/opnsense` and `GET /api/snippets/pfsense` generate XML fragments from approved and deployed firewall rules.

The snippets include manual-review comments and are not applied by the application. They are portfolio artifacts for demonstrating how the workflow could hand off reviewed configuration to a firewall administrator.

## API Endpoints

```text
GET    /api/state
GET    /api/export

GET    /api/rules
POST   /api/rules
POST   /api/rules/{id}/approve
POST   /api/rules/{id}/reject
POST   /api/rules/{id}/deploy

GET    /api/tunnels
POST   /api/tunnels
POST   /api/tunnels/{id}/approve
POST   /api/tunnels/{id}/reject
POST   /api/tunnels/{id}/status

GET    /api/checks
POST   /api/checks/run

GET    /api/lab-targets
POST   /api/lab-targets
POST   /api/lab-targets/{id}/toggle
POST   /api/lab-checks/run

GET    /api/snippets/{platform}

GET    /api/audit
POST   /api/reset
```

## Safety Boundary

The app never changes the real operating system firewall.

Deployment commands and OPNsense/pfSense snippets are generated for review only. A production-quality tool would require authentication, authorization, approvals, logging, rollback, and strong environment isolation before any real command execution or configuration import.
