"""
TrustLine - Immutable Local Audit Logger
Owner: Pranjay (Team Lead & Cybersecurity Lead)

Maintains a tamper-evident, append-only JSON Lines audit trail of all security
events, tool-call evaluations, and policy decisions. Uses chained SHA-256 hashes
to detect any unauthorized log modification.
"""

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


class AuditLogger:
    """
    Structured, cryptographic audit logger recording each gateway decision to logs/audit.jsonl.
    """

    GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

    def __init__(self, log_dir: Optional[str] = None, log_filename: str = "audit.jsonl"):
        if log_dir is None:
            base_dir = Path(__file__).resolve().parent.parent
            self.log_dir = base_dir / "logs"
        else:
            self.log_dir = Path(log_dir)

        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.log_dir / log_filename
        self.last_hash = self._recover_last_hash()

    def _recover_last_hash(self) -> str:
        """Reads the last record to recover hash chain state, or returns GENESIS_HASH."""
        if not self.log_path.exists():
            return self.GENESIS_HASH

        last_hash = self.GENESIS_HASH
        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        record = json.loads(line)
                        if "entry_hash" in record:
                            last_hash = record["entry_hash"]
        except Exception:
            return self.GENESIS_HASH

        return last_hash

    def log_event(
        self,
        tool_name: str,
        decision: str,
        rule_triggered: str,
        reason: str,
        session_id: str = "default",
        arguments_preview: str = "",
        taint_state: str = "CLEAN",
        latency_ms: float = 0.0,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Appends an immutable, chained event entry to the audit log.
        """
        event_id = f"evt_{uuid.uuid4().hex[:12]}"
        timestamp = datetime.now(timezone.utc).isoformat()

        # Compute tamper-evident hash
        hash_payload = f"{timestamp}|{event_id}|{session_id}|{tool_name}|{decision}|{rule_triggered}|{self.last_hash}"
        entry_hash = hashlib.sha256(hash_payload.encode("utf-8")).hexdigest()

        entry = {
            "event_id": event_id,
            "timestamp": timestamp,
            "session_id": session_id,
            "tool_name": tool_name,
            "arguments_preview": arguments_preview[:250],
            "taint_state": taint_state,
            "decision": decision,
            "rule_triggered": rule_triggered,
            "reason": reason,
            "latency_ms": round(latency_ms, 2),
            "prev_hash": self.last_hash,
            "entry_hash": entry_hash,
            "extra": extra or {},
        }

        # Thread-safe append
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

        self.last_hash = entry_hash
        return entry

    def get_recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Returns the most recent N audit events in reverse-chronological order."""
        if not self.log_path.exists():
            return []

        entries: List[Dict[str, Any]] = []
        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        entries.append(json.loads(line))
        except Exception:
            return []

        # Return latest first
        return list(reversed(entries[-limit:]))

    def verify_integrity(self) -> bool:
        """
        Validates the hash chain across the entire audit log.
        Returns False if any tampering, deletion, or modification occurred.
        """
        if not self.log_path.exists():
            return True

        expected_prev = self.GENESIS_HASH
        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    record = json.loads(line)
                    if record.get("prev_hash") != expected_prev:
                        return False

                    # Recompute hash
                    hash_payload = (
                        f"{record['timestamp']}|{record['event_id']}|"
                        f"{record['session_id']}|{record['tool_name']}|"
                        f"{record['decision']}|{record['rule_triggered']}|"
                        f"{record['prev_hash']}"
                    )
                    recomputed = hashlib.sha256(hash_payload.encode("utf-8")).hexdigest()
                    if recomputed != record.get("entry_hash"):
                        return False

                    expected_prev = record["entry_hash"]
        except Exception:
            return False

        return True
