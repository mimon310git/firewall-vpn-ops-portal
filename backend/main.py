from __future__ import annotations

import os
import socket
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATABASE = PROJECT_ROOT / "data" / "ops_portal.sqlite3"
LAB_MODE_ENV = "OPS_PORTAL_LAB_MODE"

ROLES = ("requester", "approver", "operator")
SNIPPET_PLATFORMS = ("opnsense", "pfsense")


DEMO_RULES = [
    {
        "id": "FW-1001",
        "source": "10.10.10.0/24",
        "destination": "10.10.20.10",
        "protocol": "TCP",
        "port": "443",
        "reason": "User access to internal web application",
        "owner": "network.ops",
        "ticketId": "SEC-1001",
        "expiresAt": "2026-08-14",
        "status": "deployed",
        "risk": "low",
        "createdAt": "2026-05-14 09:00",
    },
    {
        "id": "FW-1002",
        "source": "10.99.99.0/24",
        "destination": "10.10.30.10",
        "protocol": "TCP",
        "port": "3389",
        "reason": "Remote admin access to jump host",
        "owner": "sec.ops",
        "ticketId": "SEC-1002",
        "expiresAt": "2026-06-14",
        "status": "approved",
        "risk": "medium",
        "createdAt": "2026-05-14 09:08",
    },
    {
        "id": "FW-1003",
        "source": "0.0.0.0/0",
        "destination": "10.10.40.10",
        "protocol": "TCP",
        "port": "443",
        "reason": "Temporary external publishing test",
        "owner": "app.owner",
        "ticketId": "CHG-1003",
        "expiresAt": "2026-05-21",
        "status": "pending",
        "risk": "high",
        "createdAt": "2026-05-14 09:12",
    },
]

DEMO_TUNNELS = [
    {
        "id": "VPN-2001",
        "name": "HQ-BRANCH-IPSEC",
        "type": "IPsec",
        "peer": "198.51.100.20",
        "localNet": "10.10.20.0/24",
        "remoteNet": "10.20.10.0/24",
        "owner": "network.ops",
        "status": "up",
        "lastCheck": "2026-05-14 09:15",
    },
    {
        "id": "VPN-2002",
        "name": "OPS-REMOTE-ACCESS",
        "type": "OpenVPN",
        "peer": "vpn.ops.local",
        "localNet": "10.10.30.0/24",
        "remoteNet": "10.99.99.0/24",
        "owner": "sec.ops",
        "status": "up",
        "lastCheck": "2026-05-14 09:18",
    },
]

DEMO_CHECKS = [
    {
        "id": "CHK-1",
        "name": "HQ web app HTTPS",
        "target": "10.10.20.10:443",
        "type": "HTTPS",
        "status": "ok",
        "detail": "TLS handshake and HTTP response completed",
        "latency": 34,
        "lastRun": "2026-05-14 09:18",
    },
    {
        "id": "CHK-2",
        "name": "Branch to HQ server",
        "target": "10.20.10.50 -> 10.10.20.10",
        "type": "IPsec flow",
        "status": "ok",
        "detail": "IPsec SA active and route reachable",
        "latency": 42,
        "lastRun": "2026-05-14 09:18",
    },
    {
        "id": "CHK-3",
        "name": "VPN admin to MGMT",
        "target": "10.99.99.0/24 -> 10.10.30.10",
        "type": "OpenVPN flow",
        "status": "fail",
        "detail": "OpenVPN rule missing for TCP/3389",
        "latency": 0,
        "lastRun": "2026-05-14 09:18",
    },
    {
        "id": "CHK-4",
        "name": "DNS resolver",
        "target": "10.10.30.53",
        "type": "DNS",
        "status": "ok",
        "detail": "A record lookup resolved successfully",
        "latency": 18,
        "lastRun": "2026-05-14 09:18",
    },
]

DEMO_AUDIT = [
    {
        "id": "AUD-1",
        "at": "2026-05-14 09:18",
        "actor": "system",
        "action": "Health checks completed",
        "target": "4 checks",
    },
    {
        "id": "AUD-2",
        "at": "2026-05-14 09:12",
        "actor": "app.owner",
        "action": "Created firewall request",
        "target": "FW-1003",
    },
    {
        "id": "AUD-3",
        "at": "2026-05-14 09:08",
        "actor": "sec.ops",
        "action": "Approved firewall request",
        "target": "FW-1002",
    },
]

DEMO_LAB_TARGETS = [
    {
        "id": "LAB-3001",
        "name": "OPNsense lab UI",
        "kind": "tcp",
        "host": "192.0.2.10",
        "port": 443,
        "enabled": 1,
        "lastStatus": "not_run",
        "lastDetail": "Waiting for controlled lab mode",
        "lastRun": "not checked",
    },
    {
        "id": "LAB-3002",
        "name": "Branch firewall SSH",
        "kind": "tcp",
        "host": "192.0.2.20",
        "port": 22,
        "enabled": 0,
        "lastStatus": "disabled",
        "lastDetail": "Disabled until a lab endpoint is configured",
        "lastRun": "not checked",
    },
]


class RuleCreate(BaseModel):
    source: str
    destination: str
    protocol: str
    port: str = ""
    reason: str
    owner: str
    ticketId: str = ""
    expiresAt: str = ""


class TunnelCreate(BaseModel):
    name: str
    type: str
    peer: str
    localNet: str
    remoteNet: str
    owner: str


class TunnelStatusUpdate(BaseModel):
    status: str


class LabTargetCreate(BaseModel):
    name: str
    kind: str = "tcp"
    host: str
    port: int
    enabled: bool = True


class LabTargetToggle(BaseModel):
    enabled: bool


@dataclass(frozen=True)
class Actor:
    role: str
    name: str


def create_app(
    database_path: str | Path | None = None,
    static_root: str | Path | None = None,
) -> FastAPI:
    app = FastAPI(title="Firewall VPN Ops Portal API", version="3.0")
    db_path = Path(database_path or DEFAULT_DATABASE)
    static_path = Path(static_root or PROJECT_ROOT)

    init_database(db_path)
    app.state.database_path = db_path
    app.state.static_root = static_path

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    assets_path = static_path / "assets"
    if assets_path.exists():
        app.mount("/assets", StaticFiles(directory=assets_path), name="assets")

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(static_path / "index.html")

    @app.get("/api/state")
    def get_state(
        db: sqlite3.Connection = Depends(get_db),
        actor: Actor = Depends(require_roles(*ROLES)),
    ) -> dict[str, Any]:
        return build_state(db, actor)

    @app.get("/api/export")
    def export_state(
        db: sqlite3.Connection = Depends(get_db),
        actor: Actor = Depends(require_roles(*ROLES)),
    ) -> dict[str, Any]:
        return build_state(db, actor)

    @app.get("/api/rules")
    def get_rules(db: sqlite3.Connection = Depends(get_db)) -> list[dict[str, Any]]:
        return list_rules(db)

    @app.post("/api/rules", status_code=201)
    def create_rule(
        payload: RuleCreate,
        db: sqlite3.Connection = Depends(get_db),
        actor: Actor = Depends(require_roles("requester")),
    ) -> dict[str, Any]:
        rule = normalize_rule(payload)
        validate_rule(db, rule)

        rule_id = next_id(db, "rules", "FW", 1000)
        db.execute(
            """
            INSERT INTO rules (
                id, source, destination, protocol, port, reason, owner,
                ticket_id, expires_at, status, risk, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                rule_id,
                rule["source"],
                rule["destination"],
                rule["protocol"],
                rule["port"],
                rule["reason"],
                rule["owner"],
                rule["ticketId"],
                rule["expiresAt"],
                "pending",
                calculate_risk(rule),
                now_stamp(),
            ),
        )
        add_audit(db, actor.name, "Created firewall request", rule_id)
        db.commit()
        return get_rule(db, rule_id)

    @app.post("/api/rules/{rule_id}/approve")
    def approve_rule(
        rule_id: str,
        db: sqlite3.Connection = Depends(get_db),
        actor: Actor = Depends(require_roles("approver")),
    ) -> dict[str, Any]:
        rule = get_rule(db, rule_id)
        if rule["status"] != "pending":
            raise HTTPException(status_code=409, detail="Only pending rules can be approved.")
        db.execute("UPDATE rules SET status = ? WHERE id = ?", ("approved", rule_id))
        add_audit(db, actor.name, "Approved firewall request", rule_id)
        db.commit()
        return get_rule(db, rule_id)

    @app.post("/api/rules/{rule_id}/reject")
    def reject_rule(
        rule_id: str,
        db: sqlite3.Connection = Depends(get_db),
        actor: Actor = Depends(require_roles("approver")),
    ) -> dict[str, Any]:
        rule = get_rule(db, rule_id)
        if rule["status"] != "pending":
            raise HTTPException(status_code=409, detail="Only pending rules can be rejected.")
        db.execute("UPDATE rules SET status = ? WHERE id = ?", ("rejected", rule_id))
        add_audit(db, actor.name, "Rejected firewall request", rule_id)
        db.commit()
        return get_rule(db, rule_id)

    @app.post("/api/rules/{rule_id}/deploy")
    def deploy_rule(
        rule_id: str,
        db: sqlite3.Connection = Depends(get_db),
        actor: Actor = Depends(require_roles("operator")),
    ) -> dict[str, Any]:
        rule = get_rule(db, rule_id)
        if rule["status"] != "approved":
            raise HTTPException(status_code=409, detail="Only approved rules can be deployed.")
        db.execute("UPDATE rules SET status = ? WHERE id = ?", ("deployed", rule_id))
        add_audit(db, actor.name, "Marked firewall rule as deployed", rule_id)
        db.commit()
        return get_rule(db, rule_id)

    @app.get("/api/tunnels")
    def get_tunnels(db: sqlite3.Connection = Depends(get_db)) -> list[dict[str, Any]]:
        return list_tunnels(db)

    @app.post("/api/tunnels", status_code=201)
    def create_tunnel(
        payload: TunnelCreate,
        db: sqlite3.Connection = Depends(get_db),
        actor: Actor = Depends(require_roles("requester")),
    ) -> dict[str, Any]:
        tunnel = normalize_tunnel(payload)
        validate_tunnel(tunnel)

        tunnel_id = next_id(db, "tunnels", "VPN", 2000)
        db.execute(
            """
            INSERT INTO tunnels (
                id, name, type, peer, local_net, remote_net, owner, status, last_check
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tunnel_id,
                tunnel["name"],
                tunnel["type"],
                tunnel["peer"],
                tunnel["localNet"],
                tunnel["remoteNet"],
                tunnel["owner"],
                "pending",
                "not checked",
            ),
        )
        add_audit(db, actor.name, "Created VPN entry", tunnel_id)
        db.commit()
        return get_tunnel(db, tunnel_id)

    @app.post("/api/tunnels/{tunnel_id}/approve")
    def approve_tunnel(
        tunnel_id: str,
        db: sqlite3.Connection = Depends(get_db),
        actor: Actor = Depends(require_roles("approver")),
    ) -> dict[str, Any]:
        tunnel = get_tunnel(db, tunnel_id)
        if tunnel["status"] != "pending":
            raise HTTPException(status_code=409, detail="Only pending tunnels can be approved.")
        set_tunnel_status(db, tunnel_id, "up")
        add_audit(db, actor.name, "Approved VPN tunnel", tunnel_id)
        db.commit()
        return get_tunnel(db, tunnel_id)

    @app.post("/api/tunnels/{tunnel_id}/reject")
    def reject_tunnel(
        tunnel_id: str,
        db: sqlite3.Connection = Depends(get_db),
        actor: Actor = Depends(require_roles("approver")),
    ) -> dict[str, Any]:
        tunnel = get_tunnel(db, tunnel_id)
        if tunnel["status"] != "pending":
            raise HTTPException(status_code=409, detail="Only pending tunnels can be rejected.")
        set_tunnel_status(db, tunnel_id, "down")
        add_audit(db, actor.name, "Rejected VPN tunnel", tunnel_id)
        db.commit()
        return get_tunnel(db, tunnel_id)

    @app.post("/api/tunnels/{tunnel_id}/status")
    def update_tunnel_status(
        tunnel_id: str,
        payload: TunnelStatusUpdate,
        db: sqlite3.Connection = Depends(get_db),
        actor: Actor = Depends(require_roles("operator")),
    ) -> dict[str, Any]:
        status = clean(payload.status).lower()
        if status not in {"up", "down"}:
            raise HTTPException(status_code=422, detail="Tunnel status must be up or down.")
        get_tunnel(db, tunnel_id)
        set_tunnel_status(db, tunnel_id, status)
        add_audit(db, actor.name, f"Marked VPN tunnel {status}", tunnel_id)
        db.commit()
        return get_tunnel(db, tunnel_id)

    @app.get("/api/checks")
    def get_checks(db: sqlite3.Connection = Depends(get_db)) -> list[dict[str, Any]]:
        return list_checks(db)

    @app.post("/api/checks/run")
    def run_checks(
        db: sqlite3.Connection = Depends(get_db),
        actor: Actor = Depends(require_roles("operator")),
    ) -> list[dict[str, Any]]:
        checks = run_health_checks(db)
        add_audit(db, actor.name, "Health checks completed", f"{len(checks)} checks")
        db.commit()
        return checks

    @app.get("/api/audit")
    def get_audit(db: sqlite3.Connection = Depends(get_db)) -> list[dict[str, Any]]:
        return list_audit(db)

    @app.get("/api/lab-targets")
    def get_lab_targets(db: sqlite3.Connection = Depends(get_db)) -> list[dict[str, Any]]:
        return list_lab_targets(db)

    @app.post("/api/lab-targets", status_code=201)
    def create_lab_target(
        payload: LabTargetCreate,
        db: sqlite3.Connection = Depends(get_db),
        actor: Actor = Depends(require_roles("operator")),
    ) -> dict[str, Any]:
        target = normalize_lab_target(payload)
        validate_lab_target(target)
        target_id = next_id(db, "lab_targets", "LAB", 3000)
        db.execute(
            """
            INSERT INTO lab_targets (
                id, name, kind, host, port, enabled, last_status, last_detail, last_run
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                target_id,
                target["name"],
                target["kind"],
                target["host"],
                target["port"],
                1 if target["enabled"] else 0,
                "not_run" if target["enabled"] else "disabled",
                "Waiting for controlled lab mode",
                "not checked",
            ),
        )
        add_audit(db, actor.name, "Created lab check target", target_id)
        db.commit()
        return get_lab_target(db, target_id)

    @app.post("/api/lab-targets/{target_id}/toggle")
    def toggle_lab_target(
        target_id: str,
        payload: LabTargetToggle,
        db: sqlite3.Connection = Depends(get_db),
        actor: Actor = Depends(require_roles("operator")),
    ) -> dict[str, Any]:
        get_lab_target(db, target_id)
        db.execute(
            """
            UPDATE lab_targets
            SET enabled = ?, last_status = ?, last_detail = ?
            WHERE id = ?
            """,
            (
                1 if payload.enabled else 0,
                "not_run" if payload.enabled else "disabled",
                "Waiting for controlled lab mode" if payload.enabled else "Disabled by operator",
                target_id,
            ),
        )
        action = "Enabled lab check target" if payload.enabled else "Disabled lab check target"
        add_audit(db, actor.name, action, target_id)
        db.commit()
        return get_lab_target(db, target_id)

    @app.post("/api/lab-checks/run")
    def run_lab_checks_endpoint(
        db: sqlite3.Connection = Depends(get_db),
        actor: Actor = Depends(require_roles("operator")),
    ) -> dict[str, Any]:
        result = run_lab_checks(db)
        add_audit(db, actor.name, "Lab checks completed", f"{len(result['targets'])} targets")
        db.commit()
        return result

    @app.get("/api/snippets/{platform}")
    def get_config_snippet(
        platform: str,
        db: sqlite3.Connection = Depends(get_db),
        actor: Actor = Depends(require_roles("operator")),
    ) -> dict[str, str]:
        normalized_platform = clean(platform).lower()
        if normalized_platform not in SNIPPET_PLATFORMS:
            raise HTTPException(status_code=404, detail="Snippet platform must be opnsense or pfsense.")
        return {
            "platform": normalized_platform,
            "generatedAt": now_stamp(),
            "snippet": generate_firewall_snippet(db, normalized_platform),
        }

    @app.post("/api/reset")
    def reset_demo_data(
        db: sqlite3.Connection = Depends(get_db),
        actor: Actor = Depends(require_roles("operator")),
    ) -> dict[str, Any]:
        clear_data(db)
        seed_demo_data(db)
        add_audit(db, actor.name, "Demo data reset", "workspace")
        db.commit()
        return build_state(db, actor)

    return app


def get_db(request: Request) -> Any:
    connection = connect(request.app.state.database_path)
    try:
        yield connection
    finally:
        connection.close()


def require_roles(*allowed_roles: str):
    def dependency(
        x_user_role: str = Header(default="requester"),
        x_user_name: str | None = Header(default=None),
    ) -> Actor:
        role = clean(x_user_role).lower()
        if role not in ROLES:
            raise HTTPException(status_code=400, detail=f"Role must be one of: {', '.join(ROLES)}.")
        if role not in allowed_roles:
            raise HTTPException(status_code=403, detail=f"{role} is not allowed to perform this action.")
        return Actor(role=role, name=clean(x_user_name) or role)

    return dependency


def connect(database_path: Path) -> sqlite3.Connection:
    database_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_database(database_path: Path) -> None:
    db = connect(database_path)
    try:
        create_schema(db)
        rule_count = db.execute("SELECT COUNT(*) FROM rules").fetchone()[0]
        if rule_count == 0:
            seed_demo_data(db)
        else:
            seed_demo_lab_targets(db)
        db.commit()
    finally:
        db.close()


def create_schema(db: sqlite3.Connection) -> None:
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS rules (
            id TEXT PRIMARY KEY,
            source TEXT NOT NULL,
            destination TEXT NOT NULL,
            protocol TEXT NOT NULL,
            port TEXT NOT NULL,
            reason TEXT NOT NULL,
            owner TEXT NOT NULL,
            ticket_id TEXT NOT NULL DEFAULT '',
            expires_at TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL,
            risk TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS tunnels (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            peer TEXT NOT NULL,
            local_net TEXT NOT NULL,
            remote_net TEXT NOT NULL,
            owner TEXT NOT NULL,
            status TEXT NOT NULL,
            last_check TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS checks (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            target TEXT NOT NULL,
            type TEXT NOT NULL,
            status TEXT NOT NULL,
            detail TEXT NOT NULL,
            latency INTEGER NOT NULL,
            last_run TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit (
            id TEXT PRIMARY KEY,
            at TEXT NOT NULL,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS lab_targets (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            kind TEXT NOT NULL,
            host TEXT NOT NULL,
            port INTEGER NOT NULL,
            enabled INTEGER NOT NULL,
            last_status TEXT NOT NULL,
            last_detail TEXT NOT NULL,
            last_run TEXT NOT NULL
        );
        """
    )
    ensure_column(db, "rules", "ticket_id", "TEXT NOT NULL DEFAULT ''")
    ensure_column(db, "rules", "expires_at", "TEXT NOT NULL DEFAULT ''")


def ensure_column(db: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    columns = {row["name"] for row in db.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in columns:
        db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def clear_data(db: sqlite3.Connection) -> None:
    for table in ("rules", "tunnels", "checks", "audit", "lab_targets"):
        db.execute(f"DELETE FROM {table}")


def seed_demo_data(db: sqlite3.Connection) -> None:
    for rule in DEMO_RULES:
        db.execute(
            """
            INSERT INTO rules (
                id, source, destination, protocol, port, reason, owner,
                ticket_id, expires_at, status, risk, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                rule["id"],
                rule["source"],
                rule["destination"],
                rule["protocol"],
                rule["port"],
                rule["reason"],
                rule["owner"],
                rule["ticketId"],
                rule["expiresAt"],
                rule["status"],
                rule["risk"],
                rule["createdAt"],
            ),
        )

    for tunnel in DEMO_TUNNELS:
        db.execute(
            """
            INSERT INTO tunnels (
                id, name, type, peer, local_net, remote_net, owner, status, last_check
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tunnel["id"],
                tunnel["name"],
                tunnel["type"],
                tunnel["peer"],
                tunnel["localNet"],
                tunnel["remoteNet"],
                tunnel["owner"],
                tunnel["status"],
                tunnel["lastCheck"],
            ),
        )

    for check in DEMO_CHECKS:
        db.execute(
            """
            INSERT INTO checks (
                id, name, target, type, status, detail, latency, last_run
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                check["id"],
                check["name"],
                check["target"],
                check["type"],
                check["status"],
                check["detail"],
                check["latency"],
                check["lastRun"],
            ),
        )

    for event in DEMO_AUDIT:
        db.execute(
            """
            INSERT INTO audit (id, at, actor, action, target)
            VALUES (?, ?, ?, ?, ?)
            """,
            (event["id"], event["at"], event["actor"], event["action"], event["target"]),
        )

    seed_demo_lab_targets(db)


def seed_demo_lab_targets(db: sqlite3.Connection) -> None:
    existing_lab_targets = db.execute("SELECT COUNT(*) FROM lab_targets").fetchone()[0]
    if existing_lab_targets != 0:
        return
    for target in DEMO_LAB_TARGETS:
        db.execute(
            """
            INSERT INTO lab_targets (
                id, name, kind, host, port, enabled, last_status, last_detail, last_run
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                target["id"],
                target["name"],
                target["kind"],
                target["host"],
                target["port"],
                target["enabled"],
                target["lastStatus"],
                target["lastDetail"],
                target["lastRun"],
            ),
        )


def build_state(db: sqlite3.Connection, actor: Actor) -> dict[str, Any]:
    return {
        "roles": list(ROLES),
        "currentRole": actor.role,
        "labMode": lab_mode_enabled(),
        "rules": list_rules(db),
        "tunnels": list_tunnels(db),
        "checks": list_checks(db),
        "labTargets": list_lab_targets(db),
        "audit": list_audit(db),
    }


def list_rules(db: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = db.execute("SELECT * FROM rules ORDER BY created_at DESC, id DESC").fetchall()
    return [format_rule(row) for row in rows]


def get_rule(db: sqlite3.Connection, rule_id: str) -> dict[str, Any]:
    row = db.execute("SELECT * FROM rules WHERE id = ?", (rule_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Firewall rule was not found.")
    return format_rule(row)


def format_rule(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "source": row["source"],
        "destination": row["destination"],
        "protocol": row["protocol"],
        "port": row["port"],
        "reason": row["reason"],
        "owner": row["owner"],
        "ticketId": row["ticket_id"],
        "expiresAt": row["expires_at"],
        "status": row["status"],
        "risk": row["risk"],
        "createdAt": row["created_at"],
    }


def list_tunnels(db: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = db.execute("SELECT * FROM tunnels ORDER BY id DESC").fetchall()
    return [format_tunnel(row) for row in rows]


def get_tunnel(db: sqlite3.Connection, tunnel_id: str) -> dict[str, Any]:
    row = db.execute("SELECT * FROM tunnels WHERE id = ?", (tunnel_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="VPN tunnel was not found.")
    return format_tunnel(row)


def format_tunnel(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "type": row["type"],
        "peer": row["peer"],
        "localNet": row["local_net"],
        "remoteNet": row["remote_net"],
        "owner": row["owner"],
        "status": row["status"],
        "lastCheck": row["last_check"],
    }


def list_checks(db: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = db.execute("SELECT * FROM checks ORDER BY id ASC").fetchall()
    return [format_check(row) for row in rows]


def format_check(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "target": row["target"],
        "type": row["type"],
        "status": row["status"],
        "detail": row["detail"],
        "latency": row["latency"],
        "lastRun": row["last_run"],
    }


def list_audit(db: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = db.execute("SELECT * FROM audit ORDER BY at DESC, id DESC").fetchall()
    return [dict(row) for row in rows]


def list_lab_targets(db: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = db.execute("SELECT * FROM lab_targets ORDER BY id ASC").fetchall()
    return [format_lab_target(row) for row in rows]


def get_lab_target(db: sqlite3.Connection, target_id: str) -> dict[str, Any]:
    row = db.execute("SELECT * FROM lab_targets WHERE id = ?", (target_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Lab target was not found.")
    return format_lab_target(row)


def format_lab_target(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "kind": row["kind"],
        "host": row["host"],
        "port": row["port"],
        "enabled": bool(row["enabled"]),
        "lastStatus": row["last_status"],
        "lastDetail": row["last_detail"],
        "lastRun": row["last_run"],
    }


def normalize_rule(payload: RuleCreate) -> dict[str, str]:
    protocol = clean(payload.protocol).upper()
    port = clean(payload.port)
    if protocol == "ICMP":
        port = "any"
    return {
        "source": clean(payload.source),
        "destination": clean(payload.destination),
        "protocol": protocol,
        "port": port,
        "reason": clean(payload.reason),
        "owner": clean(payload.owner),
        "ticketId": clean(payload.ticketId).upper(),
        "expiresAt": clean(payload.expiresAt),
    }


def normalize_tunnel(payload: TunnelCreate) -> dict[str, str]:
    return {
        "name": clean(payload.name),
        "type": clean(payload.type),
        "peer": clean(payload.peer),
        "localNet": clean(payload.localNet),
        "remoteNet": clean(payload.remoteNet),
        "owner": clean(payload.owner),
    }


def normalize_lab_target(payload: LabTargetCreate) -> dict[str, Any]:
    return {
        "name": clean(payload.name),
        "kind": clean(payload.kind).lower(),
        "host": clean(payload.host),
        "port": payload.port,
        "enabled": payload.enabled,
    }


def validate_rule(db: sqlite3.Connection, rule: dict[str, str]) -> None:
    if not is_network(rule["source"]):
        raise HTTPException(status_code=422, detail="Source must be a valid IP address or CIDR range.")
    if not is_network(rule["destination"]):
        raise HTTPException(status_code=422, detail="Destination must be a valid IP address or CIDR range.")
    if rule["protocol"] not in {"TCP", "UDP", "ICMP"}:
        raise HTTPException(status_code=422, detail="Protocol must be TCP, UDP, or ICMP.")
    if rule["protocol"] != "ICMP" and not is_port(rule["port"]):
        raise HTTPException(status_code=422, detail="Port must be a number between 1 and 65535.")
    if len(rule["reason"]) < 8:
        raise HTTPException(status_code=422, detail="Reason must explain why this access is needed.")
    if not rule["owner"]:
        raise HTTPException(status_code=422, detail="Owner is required.")
    if not is_ticket_id(rule["ticketId"]):
        raise HTTPException(status_code=422, detail="Ticket ID must look like SEC-123 or CHG-123.")
    if not is_expiration_date(rule["expiresAt"]):
        raise HTTPException(status_code=422, detail="Expiration date must use YYYY-MM-DD.")

    duplicate = db.execute(
        """
        SELECT 1
        FROM rules
        WHERE source = ?
          AND destination = ?
          AND protocol = ?
          AND port = ?
          AND status != 'rejected'
        LIMIT 1
        """,
        (rule["source"], rule["destination"], rule["protocol"], rule["port"]),
    ).fetchone()
    if duplicate is not None:
        raise HTTPException(status_code=409, detail="A matching active rule already exists.")


def validate_tunnel(tunnel: dict[str, str]) -> None:
    if len(tunnel["name"]) < 4:
        raise HTTPException(status_code=422, detail="Tunnel name must have at least 4 characters.")
    if tunnel["type"] not in {"IPsec", "OpenVPN", "WireGuard"}:
        raise HTTPException(status_code=422, detail="Tunnel type must be IPsec, OpenVPN, or WireGuard.")
    if not is_network(tunnel["localNet"]) or not is_network(tunnel["remoteNet"]):
        raise HTTPException(status_code=422, detail="Local and remote networks must be valid CIDR ranges.")
    if len(tunnel["peer"]) < 3:
        raise HTTPException(status_code=422, detail="Peer or endpoint is required.")
    if not tunnel["owner"]:
        raise HTTPException(status_code=422, detail="Owner is required.")


def validate_lab_target(target: dict[str, Any]) -> None:
    if len(target["name"]) < 4:
        raise HTTPException(status_code=422, detail="Lab target name must have at least 4 characters.")
    if target["kind"] != "tcp":
        raise HTTPException(status_code=422, detail="Only TCP read-only checks are supported.")
    if not is_valid_hostname(target["host"]):
        raise HTTPException(status_code=422, detail="Host must be an IP address or hostname.")
    if not isinstance(target["port"], int) or target["port"] < 1 or target["port"] > 65535:
        raise HTTPException(status_code=422, detail="Port must be a number between 1 and 65535.")


def set_tunnel_status(db: sqlite3.Connection, tunnel_id: str, status: str) -> None:
    db.execute(
        "UPDATE tunnels SET status = ?, last_check = ? WHERE id = ?",
        (status, now_stamp(), tunnel_id),
    )


def run_health_checks(db: sqlite3.Connection) -> list[dict[str, Any]]:
    rules = list_rules(db)
    tunnels = list_tunnels(db)
    current_time = now_stamp()
    updated_checks: list[dict[str, Any]] = []

    for index, check in enumerate(list_checks(db)):
        openvpn_rule_blocked = "OpenVPN" in check["type"] and any(
            rule["destination"] == "10.10.30.10" and rule["status"] != "deployed" for rule in rules
        )
        ipsec_down = check["type"] == "IPsec flow" and any(
            tunnel["type"] == "IPsec" and tunnel["status"] == "down" for tunnel in tunnels
        )
        fail = openvpn_rule_blocked or ipsec_down
        latency = 0 if fail else 18 + (index * 9)
        detail = "Policy or tunnel state blocks this flow" if fail else "Connectivity check completed successfully"

        db.execute(
            """
            UPDATE checks
            SET status = ?, latency = ?, last_run = ?, detail = ?
            WHERE id = ?
            """,
            ("fail" if fail else "ok", latency, current_time, detail, check["id"]),
        )

    updated_checks = list_checks(db)
    return updated_checks


def run_lab_checks(db: sqlite3.Connection) -> dict[str, Any]:
    enabled = lab_mode_enabled()
    current_time = now_stamp()

    for target in list_lab_targets(db):
        if not target["enabled"]:
            continue
        if not enabled:
            db.execute(
                """
                UPDATE lab_targets
                SET last_status = ?, last_detail = ?, last_run = ?
                WHERE id = ?
                """,
                (
                    "skipped",
                    f"Set {LAB_MODE_ENV}=enabled to contact configured lab hosts.",
                    current_time,
                    target["id"],
                ),
            )
            continue

        status, detail = tcp_probe(target["host"], int(target["port"]))
        db.execute(
            """
            UPDATE lab_targets
            SET last_status = ?, last_detail = ?, last_run = ?
            WHERE id = ?
            """,
            (status, detail, current_time, target["id"]),
        )

    return {
        "labMode": enabled,
        "targets": list_lab_targets(db),
    }


def tcp_probe(host: str, port: int) -> tuple[str, str]:
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=2.0):
            elapsed_ms = int((time.perf_counter() - start) * 1000)
            return "ok", f"TCP connection opened in {elapsed_ms} ms."
    except OSError as exc:
        return "fail", f"TCP connection failed: {exc}"


def generate_firewall_snippet(db: sqlite3.Connection, platform: str) -> str:
    rules = [rule for rule in list_rules(db) if rule["status"] in {"approved", "deployed"}]
    if not rules:
        return "<!-- No approved or deployed firewall rules are available for export. -->"

    rule_entries = "\n".join(format_firewall_snippet_rule(rule, platform) for rule in rules)
    title = "OPNsense" if platform == "opnsense" else "pfSense"
    return (
        f"<!-- {title} firewall rule snippet generated {now_stamp()} -->\n"
        "<!-- Manual review required before import or deployment. -->\n"
        "<filter>\n"
        f"{rule_entries}\n"
        "</filter>"
    )


def format_firewall_snippet_rule(rule: dict[str, Any], platform: str) -> str:
    description = f"{rule['id']} {rule['ticketId'] or 'no-ticket'} expires {rule['expiresAt'] or 'n/a'} - {rule['reason']}"
    port_block = "" if rule["protocol"] == "ICMP" else f"\n    <port>{escape_xml(rule['port'])}</port>"
    category = "ops-portal-review" if platform == "opnsense" else "Ops Portal Review"
    return f"""  <rule>
    <type>pass</type>
    <interface>lan</interface>
    <ipprotocol>inet</ipprotocol>
    <protocol>{escape_xml(rule["protocol"].lower())}</protocol>
    <source>
      <network>{escape_xml(rule["source"])}</network>
    </source>
    <destination>
      <address>{escape_xml(rule["destination"])}</address>{port_block}
    </destination>
    <descr>{escape_xml(description)}</descr>
    <category>{escape_xml(category)}</category>
    <disabled>0</disabled>
  </rule>"""


def next_id(db: sqlite3.Connection, table: str, prefix: str, fallback: int) -> str:
    rows = db.execute(f"SELECT id FROM {table} WHERE id LIKE ?", (f"{prefix}-%",)).fetchall()
    current_max = fallback
    for row in rows:
        try:
            current_max = max(current_max, int(str(row["id"]).split("-", 1)[1]))
        except (IndexError, ValueError):
            continue
    return f"{prefix}-{current_max + 1}"


def add_audit(db: sqlite3.Connection, actor: str, action: str, target: str) -> None:
    db.execute(
        """
        INSERT INTO audit (id, at, actor, action, target)
        VALUES (?, ?, ?, ?, ?)
        """,
        (next_id(db, "audit", "AUD", 0), now_stamp(), actor, action, target),
    )


def calculate_risk(rule: dict[str, str]) -> str:
    broad_source = rule["source"] in {"0.0.0.0/0", "any"}
    broad_destination = rule["destination"] in {"0.0.0.0/0", "any"}
    sensitive = rule["port"] in {"22", "3389", "445"}
    if broad_source or broad_destination:
        return "high"
    if sensitive or "10.10.30." in rule["destination"]:
        return "medium"
    return "low"


def is_port(value: str) -> bool:
    if not value.isdigit():
        return False
    number = int(value)
    return 1 <= number <= 65535


def is_network(value: str) -> bool:
    if value == "any":
        return True
    parts = value.split("/")
    if len(parts) > 2 or not is_ip(parts[0]):
        return False
    if len(parts) == 1:
        return True
    if not parts[1].isdigit():
        return False
    mask = int(parts[1])
    return 0 <= mask <= 32


def is_ip(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        number = int(part)
        if number < 0 or number > 255:
            return False
    return True


def is_ticket_id(value: str) -> bool:
    if not value or len(value) > 32:
        return False
    parts = value.split("-")
    if len(parts) != 2:
        return False
    prefix, number = parts
    return prefix.isalpha() and prefix.isupper() and number.isdigit()


def is_expiration_date(value: str) -> bool:
    if not value:
        return False
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        return False
    return True


def is_valid_hostname(value: str) -> bool:
    if is_ip(value):
        return True
    if len(value) > 253:
        return False
    labels = value.rstrip(".").split(".")
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not all(char.isalnum() or char == "-" for char in label):
            return False
    return True


def lab_mode_enabled() -> bool:
    return os.getenv(LAB_MODE_ENV, "").strip().lower() in {"1", "true", "yes", "enabled"}


def escape_xml(value: Any) -> str:
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def now_stamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M")


def clean(value: Any) -> str:
    return str(value or "").strip()


app = create_app()
