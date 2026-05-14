from pathlib import Path

from fastapi.testclient import TestClient

from backend.main import LAB_MODE_ENV, create_app


def make_client(tmp_path: Path) -> TestClient:
    app = create_app(database_path=tmp_path / "test.sqlite3", static_root=Path(__file__).parents[1])
    return TestClient(app)


def role_headers(role: str) -> dict[str, str]:
    return {"X-User-Role": role, "X-User-Name": f"test.{role}"}


def valid_rule() -> dict[str, str]:
    return {
        "source": "10.10.10.20",
        "destination": "10.10.20.30",
        "protocol": "TCP",
        "port": "8443",
        "reason": "Temporary QA access",
        "ticketId": "SEC-2042",
        "expiresAt": "2026-06-30",
        "owner": "qa.ops",
    }


def test_state_is_seeded(tmp_path: Path) -> None:
    client = make_client(tmp_path)

    response = client.get("/api/state", headers=role_headers("requester"))

    assert response.status_code == 200
    data = response.json()
    assert len(data["rules"]) == 3
    assert len(data["tunnels"]) == 2
    assert len(data["labTargets"]) == 2
    assert data["labMode"] is False
    assert data["rules"][0]["ticketId"]
    assert data["rules"][0]["expiresAt"]
    assert data["roles"] == ["requester", "approver", "operator"]


def test_requester_can_create_rule_and_duplicate_is_blocked(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    payload = valid_rule()

    created = client.post("/api/rules", json=payload, headers=role_headers("requester"))
    duplicate = client.post("/api/rules", json=payload, headers=role_headers("requester"))

    assert created.status_code == 201
    assert created.json()["status"] == "pending"
    assert duplicate.status_code == 409
    assert duplicate.json()["detail"] == "A matching active rule already exists."


def test_invalid_source_is_rejected(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    payload = valid_rule()
    payload["source"] = "999.10.10.1"

    response = client.post("/api/rules", json=payload, headers=role_headers("requester"))

    assert response.status_code == 422
    assert response.json()["detail"] == "Source must be a valid IP address or CIDR range."


def test_rule_approval_and_deploy_respect_roles(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    created = client.post("/api/rules", json=valid_rule(), headers=role_headers("requester")).json()

    forbidden = client.post(f"/api/rules/{created['id']}/approve", headers=role_headers("requester"))
    approved = client.post(f"/api/rules/{created['id']}/approve", headers=role_headers("approver"))
    deployed = client.post(f"/api/rules/{created['id']}/deploy", headers=role_headers("operator"))

    assert forbidden.status_code == 403
    assert approved.status_code == 200
    assert approved.json()["status"] == "approved"
    assert deployed.status_code == 200
    assert deployed.json()["status"] == "deployed"


def test_operator_can_run_health_checks(tmp_path: Path) -> None:
    client = make_client(tmp_path)

    forbidden = client.post("/api/checks/run", headers=role_headers("approver"))
    response = client.post("/api/checks/run", headers=role_headers("operator"))

    assert forbidden.status_code == 403
    assert response.status_code == 200
    assert len(response.json()) == 4


def test_operator_can_generate_firewall_snippet(tmp_path: Path) -> None:
    client = make_client(tmp_path)

    forbidden = client.get("/api/snippets/opnsense", headers=role_headers("approver"))
    response = client.get("/api/snippets/opnsense", headers=role_headers("operator"))

    assert forbidden.status_code == 403
    assert response.status_code == 200
    data = response.json()
    assert data["platform"] == "opnsense"
    assert "<filter>" in data["snippet"]
    assert "Manual review required" in data["snippet"]


def test_lab_checks_are_skipped_until_lab_mode_is_enabled(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv(LAB_MODE_ENV, raising=False)
    client = make_client(tmp_path)

    response = client.post("/api/lab-checks/run", headers=role_headers("operator"))

    assert response.status_code == 200
    data = response.json()
    assert data["labMode"] is False
    assert data["targets"][0]["lastStatus"] == "skipped"


def test_operator_can_create_lab_target(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    payload = {
        "name": "Lab API HTTPS",
        "kind": "tcp",
        "host": "192.0.2.30",
        "port": 8443,
        "enabled": True,
    }

    forbidden = client.post("/api/lab-targets", json=payload, headers=role_headers("requester"))
    created = client.post("/api/lab-targets", json=payload, headers=role_headers("operator"))

    assert forbidden.status_code == 403
    assert created.status_code == 201
    assert created.json()["host"] == "192.0.2.30"
