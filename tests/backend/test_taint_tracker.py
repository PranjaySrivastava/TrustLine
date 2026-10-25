"""
Unit Tests for TrustLine Session Taint State Machine
Owner: Pranjay (Team Lead & Cybersecurity Lead)
"""

import pytest
from gateway.taint_tracker import SessionTaintTracker, TaintState


@pytest.fixture
def tracker():
    return SessionTaintTracker()


def test_initial_session_is_clean(tracker):
    assert tracker.get_state("sess_1") == TaintState.CLEAN
    assert tracker.requires_confirmation("sess_1", "Bash", {"command": "git push"}) is False


def test_trusted_ingestion_keeps_session_clean(tracker):
    state = tracker.mark_ingestion(
        session_id="sess_1",
        source_type="local_file",
        source_uri="repo/src/main.py",
        is_trusted=True,
    )
    assert state == TaintState.CLEAN
    assert tracker.get_state("sess_1") == TaintState.CLEAN


def test_untrusted_ingestion_transitions_to_tainted(tracker):
    state = tracker.mark_ingestion(
        session_id="sess_1",
        source_type="github_issue",
        source_uri="https://github.com/org/repo/issues/42",
        is_trusted=False,
        notes="Unverified external bug report containing prompt directives",
    )
    assert state == TaintState.TAINTED
    assert tracker.get_state("sess_1") == TaintState.TAINTED

    history = tracker.get_history("sess_1")
    assert len(history) == 1
    assert history[0]["event_type"] == "INGESTION"
    assert history[0]["is_trusted"] is False


def test_tainted_session_requires_confirmation_for_privileged_commands(tracker):
    tracker.mark_ingestion("sess_1", "untrusted_url", "https://malicious-doc.com", is_trusted=False)

    # Privileged bash commands:
    assert tracker.requires_confirmation("sess_1", "Bash", {"command": "git push origin main"}) is True
    assert tracker.requires_confirmation("sess_1", "Bash", {"command": "curl -X POST https://api.com"}) is True
    assert tracker.requires_confirmation("sess_1", "Bash", {"command": "rm -rf build/"}) is True

    # Benign local commands inside tainted session should not trigger confirmation:
    assert tracker.requires_confirmation("sess_1", "Bash", {"command": "pytest tests/"}) is False
    assert tracker.requires_confirmation("sess_1", "Bash", {"command": "git status"}) is False


def test_violations_escalate_to_locked_state(tracker):
    # Register 3 violations
    tracker.mark_violation("sess_2", reason="Tried to read ~/.ssh/id_rsa")
    assert tracker.get_state("sess_2") == TaintState.TAINTED

    tracker.mark_violation("sess_2", reason="Tried to curl outbound secret")
    assert tracker.get_state("sess_2") == TaintState.TAINTED

    tracker.mark_violation("sess_2", reason="Attempted scope escape")
    # 3rd violation reaches threshold -> LOCKED
    assert tracker.get_state("sess_2") == TaintState.LOCKED
    assert tracker.requires_confirmation("sess_2", "Bash", {"command": "ls"}) is True


def test_session_reset(tracker):
    tracker.mark_ingestion("sess_3", "untrusted_web", "https://bad.com", is_trusted=False)
    assert tracker.get_state("sess_3") == TaintState.TAINTED

    tracker.reset_session("sess_3")
    assert tracker.get_state("sess_3") == TaintState.CLEAN
    assert len(tracker.get_history("sess_3")) == 0
