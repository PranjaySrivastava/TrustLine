"""
Unit Tests for TrustLine Gateway Server
Owner: Pranjay (Backend Core)
"""

import pytest
from fastapi.testclient import TestClient
from gateway.server import app


@pytest.fixture
def client():
    return TestClient(app)


def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["armed_canaries"] >= 1


def test_api_inspect_benign(client):
    req = {
        "sessionId": "test_api_sess",
        "toolName": "Bash",
        "toolInput": {"command": "git status"},
    }
    response = client.post("/api/inspect", json=req)
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "allow"
    assert data["ruleTriggered"] == "RULE_PERMITTED_SCOPE"
    assert data["latencyMs"] >= 0


def test_api_inspect_ssh_blocked(client):
    req = {
        "sessionId": "test_api_sess",
        "toolName": "Bash",
        "toolInput": {"command": "cat ~/.ssh/id_rsa"},
    }
    response = client.post("/api/inspect", json=req)
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "deny"
    assert data["ruleTriggered"] == "RULE_SCOPE_BOUNDARY"


def test_api_simulation_scenarios(client):
    # Benign simulation -> allow
    r1 = client.post("/api/simulate", json={"scenario": "benign_task"})
    assert r1.status_code == 200
    assert r1.json()["decision"] == "allow"

    # README injection simulation -> deny
    r2 = client.post("/api/simulate", json={"scenario": "readme_injection"})
    assert r2.status_code == 200
    assert r2.json()["decision"] == "deny"

    # Base64 leak simulation -> deny
    r3 = client.post("/api/simulate", json={"scenario": "base64_leak"})
    assert r3.status_code == 200
    assert r3.json()["decision"] == "deny"

    # Tainted push simulation -> ask
    r4 = client.post("/api/simulate", json={"scenario": "taint_push"})
    assert r4.status_code == 200
    assert r4.json()["decision"] == "ask"


def test_api_confirm_endpoint(client):
    resp = client.post("/api/confirm", json={"eventId": "evt_test_1", "decision": "allow"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "resolved"


def test_api_events_retrieval(client):
    resp = client.get("/api/events")
    assert resp.status_code == 200
    data = resp.json()
    assert "events" in data
    assert "armedCanaries" in data
