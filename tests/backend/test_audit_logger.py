"""
Unit Tests for TrustLine Audit Logger
Owner: Pranjay (Team Lead & Cybersecurity Lead)
"""

import json
import pytest
from gateway.audit_logger import AuditLogger


@pytest.fixture
def logger(tmp_path):
    return AuditLogger(log_dir=str(tmp_path))


def test_log_event_creation(logger):
    entry = logger.log_event(
        tool_name="Bash",
        decision="deny",
        rule_triggered="RULE_CANARY_EGRESS_BLOCKED",
        reason="Detected canary secret",
        session_id="sess_123",
        arguments_preview="curl ...",
        taint_state="TAINTED",
        latency_ms=12.5,
    )

    assert entry["event_id"].startswith("evt_")
    assert entry["decision"] == "deny"
    assert entry["prev_hash"] == AuditLogger.GENESIS_HASH
    assert len(entry["entry_hash"]) == 64


def test_audit_integrity_chain(logger):
    # Log 3 sequential events
    logger.log_event(tool_name="Read", decision="allow", rule_triggered="SCOPE", reason="ok")
    logger.log_event(tool_name="Write", decision="allow", rule_triggered="SCOPE", reason="ok")
    logger.log_event(tool_name="Bash", decision="deny", rule_triggered="CANARY", reason="leak")

    assert logger.verify_integrity() is True
    recent = logger.get_recent_events(limit=10)
    assert len(recent) == 3
    # Latest first:
    assert recent[0]["tool_name"] == "Bash"
    assert recent[2]["tool_name"] == "Read"


def test_tamper_detection(logger):
    logger.log_event(tool_name="Read", decision="allow", rule_triggered="SCOPE", reason="ok")
    logger.log_event(tool_name="Bash", decision="deny", rule_triggered="CANARY", reason="leak")
    assert logger.verify_integrity() is True

    # Tamper with the log file directly
    with open(logger.log_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    # Modify the first record's decision from allow to deny
    modified_record = json.loads(lines[0])
    modified_record["decision"] = "deny"
    lines[0] = json.dumps(modified_record) + "\n"

    with open(logger.log_path, "w", encoding="utf-8") as f:
        f.writelines(lines)

    # Verification must fail!
    assert logger.verify_integrity() is False
