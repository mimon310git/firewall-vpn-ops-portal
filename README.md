# Firewall VPN Ops Portal

A local FastAPI web app for practicing firewall and VPN change operations.

This is a portfolio-style project, not a real firewall controller. It simulates the workflow used in an operations team:

- create firewall rule requests
- validate source and destination networks
- review pending changes
- approve or reject requests
- generate a simulated deployment command
- track VPN tunnels
- run simulated health checks
- generate OPNsense and pfSense firewall snippets for manual review
- run read-only lab checks only when controlled lab mode is enabled
- keep an audit log in SQLite

## How To Run

Create a virtual environment, install dependencies, and start the FastAPI app:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m uvicorn backend.main:app --reload
```

Then open:

```text
http://127.0.0.1:8000
```

The backend stores demo data and local changes in SQLite at `data/ops_portal.sqlite3`.

Real lab probes are disabled by default. To allow read-only TCP checks against configured lab hosts, start the backend with:

```powershell
$env:OPS_PORTAL_LAB_MODE = "enabled"
python -m uvicorn backend.main:app --reload
```

## How To Test

Run the API tests with:

```powershell
python -m pytest
```

## What The App Does

### Firewall Rules

The app lets you create a firewall rule request with:

- source IP or CIDR
- destination IP or CIDR
- protocol
- port
- business reason
- owner

It validates the input and blocks common mistakes such as invalid IP ranges, invalid ports, and duplicate active rules.

The UI includes a port reference and rule review notes for common operational decisions:

- `22` SSH and `3389` RDP are treated as admin access and raise risk.
- `445` SMB is treated as sensitive internal access.
- `500/4500`, `1194`, and `51820` map to common VPN services.
- `0.0.0.0/0` and other broad exposure patterns are marked high risk.
- Good requests include a business reason, owner, expected protocol, and scoped source/destination.

The app also has a `Theory` section with a short reference for common ports, rule review, risk scoring, and the operational change lifecycle.

### Approval Workflow

Firewall changes start as `pending`.

They can move through:

```text
pending -> approved -> deployed
pending -> rejected
```

Approved rules can generate a simulated `ufw` command. The command is intentionally not executed.

Role permissions are enforced by the API:

- `requester` creates firewall rules and VPN entries
- `approver` approves or rejects pending requests
- `operator` deploys approved firewall rules, updates VPN state, runs checks, manages lab targets, generates snippets, and resets demo data

### VPN Tunnels

The VPN inventory tracks:

- IPsec
- OpenVPN
- WireGuard

Each entry stores local network, remote network, peer endpoint, owner, status, and last check time.

### Health Checks

The health check page simulates checks for:

- HTTPS service reachability
- IPsec branch-to-HQ flow
- OpenVPN admin access
- DNS resolver availability

The checks react to app state. For example, if the OpenVPN admin firewall rule is not deployed, the related health check can fail.

### Lab Tools

The lab tools page adds Version 3 behavior:

- OPNsense and pfSense XML snippets generated from approved and deployed firewall rules
- manual-review comments inside generated snippets
- configurable lab targets stored in SQLite
- read-only TCP probes that are skipped unless `OPS_PORTAL_LAB_MODE=enabled`

No generated snippet is imported automatically and no firewall command is executed by the app.

## Portfolio Roadmap

### Version 1

- Static app with local data
- Firewall rule form
- VPN inventory
- Approval queue
- Audit log
- Simulated checks

### Version 2

- FastAPI backend
- SQLite persistence
- API tests
- User roles: requester, approver, operator

### Version 3

- Controlled lab mode through `OPS_PORTAL_LAB_MODE=enabled`
- OPNsense and pfSense export snippets
- Read-only lab health checks against configured hosts
- Manual review boundary for generated commands and snippets

## Interview Explanation

Short version:

```text
I built a small operations portal that simulates firewall and VPN change management. It validates network inputs, tracks approval state, generates deployment commands, runs health checks, and keeps an audit log. I used it to practice both networking concepts and QA automation scenarios.
```

Stronger version:

```text
The project models a real operational workflow: a requester opens a firewall or VPN change, the app validates the network data, an approver reviews risk, and the operator marks it deployed. I also included health checks, gated lab checks, firewall export snippets, and audit history so the project is useful for testing and troubleshooting scenarios, not only CRUD screens.
```
