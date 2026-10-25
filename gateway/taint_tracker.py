"""
TrustLine - Session Taint State Machine
Owner: Pranjay (Team Lead & Cybersecurity Lead)

Tracks session risk lifecycle across three primary states:
  CLEAN   -> Normal execution within verified local scope.
  TAINTED -> External, untrusted content has been ingested (public issues, untrusted READMEs, web fetches).
  LOCKED  -> Repeated violations or critical risk detected; sensitive actions locked.

Enforces human-in-the-loop escalation (ASK) for privileged or egress actions when tainted.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class TaintState(str, Enum):
    CLEAN = "CLEAN"
    TAINTED = "TAINTED"
    LOCKED = "LOCKED"


class TaintRecord:
    """Historical entry recording what caused a session to transition or escalate."""

    def __init__(
        self,
        event_type: str,
        source_type: str,
        source_uri: str,
        is_trusted: bool,
        notes: str = "",
    ):
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.event_type = event_type
        self.source_type = source_type
        self.source_uri = source_uri
        self.is_trusted = is_trusted
        self.notes = notes

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "source_type": self.source_type,
            "source_uri": self.source_uri,
            "is_trusted": self.is_trusted,
            "notes": self.notes,
        }


class SessionTaintTracker:
    """
    Manages session taint states, tracks untrusted data provenance,
    and determines when privileged actions require explicit user confirmation.
    """

    # Privileged commands or tool patterns that require confirmation if tainted
    PRIVILEGED_BASH_PATTERNS = [
        "git push",
        "rm -rf",
        "rm -r",
        "del /s",
        "rmdir /s",
        "curl ",
        "wget ",
        "Invoke-WebRequest",
        "Invoke-RestMethod",
        "nc ",
        "netcat",
        "ssh ",
        "scp ",
        "rsync ",
    ]

    PRIVILEGED_TOOLS = {
        "git_push",
        "delete_file",
        "execute_shell",
        "bash",
        "terminal",
    }

    VIOLATION_THRESHOLD_FOR_LOCK = 3

    def __init__(self):
        self._states: Dict[str, TaintState] = {}
        self._history: Dict[str, List[TaintRecord]] = {}
        self._violations: Dict[str, int] = {}

    def get_state(self, session_id: str = "default") -> TaintState:
        """Returns the current taint state for a session, default CLEAN."""
        return self._states.get(session_id, TaintState.CLEAN)

    def mark_ingestion(
        self,
        session_id: str = "default",
        source_type: str = "untrusted_file",
        source_uri: str = "unknown",
        is_trusted: bool = False,
        notes: str = "",
    ) -> TaintState:
        """
        Records content ingestion into the agent session.
        If untrusted, transitions CLEAN -> TAINTED.
        """
        current_state = self.get_state(session_id)
        record = TaintRecord(
            event_type="INGESTION",
            source_type=source_type,
            source_uri=source_uri,
            is_trusted=is_trusted,
            notes=notes,
        )

        if session_id not in self._history:
            self._history[session_id] = []
        self._history[session_id].append(record)

        if not is_trusted and current_state == TaintState.CLEAN:
            self._states[session_id] = TaintState.TAINTED

        return self.get_state(session_id)

    def mark_violation(self, session_id: str = "default", reason: str = "") -> TaintState:
        """
        Records a policy violation against the session.
        Repeated violations transition the session to LOCKED.
        """
        current_state = self.get_state(session_id)
        self._violations[session_id] = self._violations.get(session_id, 0) + 1

        record = TaintRecord(
            event_type="VIOLATION",
            source_type="policy_engine",
            source_uri="violation_trigger",
            is_trusted=False,
            notes=reason,
        )
        if session_id not in self._history:
            self._history[session_id] = []
        self._history[session_id].append(record)

        if self._violations[session_id] >= self.VIOLATION_THRESHOLD_FOR_LOCK:
            self._states[session_id] = TaintState.LOCKED
        elif current_state == TaintState.CLEAN:
            self._states[session_id] = TaintState.TAINTED

        return self.get_state(session_id)

    def set_state(self, session_id: str, state: TaintState) -> None:
        """Explicitly sets session state (e.g., following manual admin unlock)."""
        self._states[session_id] = state

    def requires_confirmation(
        self,
        session_id: str,
        tool_name: str,
        tool_input: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Determines whether the proposed tool call requires human-in-the-loop confirmation.
        """
        state = self.get_state(session_id)
        if state == TaintState.CLEAN:
            return False

        if state == TaintState.LOCKED:
            # Locked sessions require confirmation or denial for all privileged calls
            return True

        # State is TAINTED: check tool name and arguments for privileged actions
        normalized_tool = tool_name.strip().lower()
        if normalized_tool in self.PRIVILEGED_TOOLS:
            # If tool is generic bash/shell, inspect the actual command line
            if normalized_tool in {"bash", "terminal", "execute_shell"}:
                command = ""
                if tool_input and isinstance(tool_input, dict):
                    command = str(tool_input.get("command", "")).lower()
                for pattern in self.PRIVILEGED_BASH_PATTERNS:
                    if pattern in command:
                        return True
            else:
                return True

        return False

    def get_history(self, session_id: str = "default") -> List[Dict[str, Any]]:
        """Returns the chronological provenance history for a session."""
        records = self._history.get(session_id, [])
        return [r.to_dict() for r in records]

    def reset_session(self, session_id: str = "default") -> None:
        """Resets session state to CLEAN and clears history."""
        self._states[session_id] = TaintState.CLEAN
        self._history[session_id] = []
        self._violations[session_id] = 0
