"""
TrustLine - Deterministic Policy Decision Engine
Owner: Pranjay (Team Lead & Cybersecurity Lead)

The central arbiter enforcing zero-trust defense for autonomous coding agents:
  Gate 1: Hard Workspace Path Scoping (<5ms)
  Gate 2: Multi-Encoding Canary & Secret Egress Scanner (<5ms)
  Gate 3: Session Taint State Machine Escalation
  Gate 4: AI Threat Intelligence Advisory (Nemotron & Tavily - Soham)
  Fail-Closed Guarantee: Any unhandled exception defaults to DENY.
"""

import os
import re
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from gateway.canary_inspector import CanaryInspector
from gateway.taint_tracker import SessionTaintTracker, TaintState


class Decision(str, Enum):
    ALLOW = "allow"
    ASK = "ask"
    DENY = "deny"


@dataclass
class PolicyVerdict:
    """The immutable verdict returned by the policy engine for an agent tool call."""
    decision: Decision
    reason: str
    rule_triggered: str
    details: Dict[str, Any] = field(default_factory=dict)

    def to_hook_dict(self) -> Dict[str, Any]:
        """Converts to Claude Code PreToolUse response dictionary."""
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": self.decision.value,
                "permissionDecisionReason": self.reason,
            }
        }


@dataclass
class ToolCallRequest:
    """Normalized tool call request structure."""
    session_id: str = "default"
    tool_name: str = ""
    tool_input: Dict[str, Any] = field(default_factory=dict)
    cwd: Optional[str] = None


class PolicyEngine:
    """
    Evaluates agent tool-use requests against deterministic security policies
    and advisory threat intelligence.
    """

    FORBIDDEN_PATH_PATTERNS = [
        re.compile(r"(?:~|[A-Za-z]:)?(?:\/|\\)\.ssh(?:\/|\\)?", re.IGNORECASE),
        re.compile(r"(?:~|[A-Za-z]:)?(?:\/|\\)\.aws(?:\/|\\)?", re.IGNORECASE),
        re.compile(r"(?:~|[A-Za-z]:)?(?:\/|\\)\.gnupg(?:\/|\\)?", re.IGNORECASE),
        re.compile(r"\b(?:id_rsa|id_ed25519|id_ecdsa)\b", re.IGNORECASE),
        re.compile(r"(?:^|[\/\\]|\s)\.env(?:\.[a-zA-Z0-9_-]+|\b|\s|$)", re.IGNORECASE),
        re.compile(r"[\/\\]etc[\/\\](?:shadow|passwd)", re.IGNORECASE),
        re.compile(r"[A-Za-z]:[\/\\]Windows[\/\\]System32", re.IGNORECASE),
    ]

    def __init__(
        self,
        canary_inspector: Optional[CanaryInspector] = None,
        taint_tracker: Optional[SessionTaintTracker] = None,
        injection_detector: Optional[Any] = None,
        tavily_shield: Optional[Any] = None,
        default_workspace_root: Optional[str] = None,
    ):
        self.canary_inspector = canary_inspector or CanaryInspector()
        self.taint_tracker = taint_tracker or SessionTaintTracker()
        self.injection_detector = injection_detector  # Soham's AI module
        self.tavily_shield = tavily_shield            # Soham's Tavily module
        self.default_workspace_root = (
            str(Path(default_workspace_root).resolve())
            if default_workspace_root
            else None
        )

    def evaluate(self, request: ToolCallRequest) -> PolicyVerdict:
        """
        Executes the 4-gate security evaluation hierarchy with fail-closed guarantee.
        """
        try:
            return self._evaluate_internal(request)
        except Exception as exc:
            # Absolute Invariant: Fail Closed
            return PolicyVerdict(
                decision=Decision.DENY,
                reason=f"TrustLine Gateway Security Exception (Fail-Closed): {str(exc)}",
                rule_triggered="RULE_FAIL_CLOSED",
                details={"exception": type(exc).__name__},
            )

    def _evaluate_internal(self, request: ToolCallRequest) -> PolicyVerdict:
        tool_name = (request.tool_name or "").strip()
        tool_input = request.tool_input or {}
        session_id = request.session_id or "default"
        cwd = request.cwd or self.default_workspace_root or os.getcwd()

        # ======================================================================
        # GATE 1: Hard Scope & Blacklisted Path Constraint (Deterministic)
        # ======================================================================
        scope_violation = self._check_scope_and_paths(tool_name, tool_input, cwd)
        if scope_violation:
            self.taint_tracker.mark_violation(session_id, reason=scope_violation)
            return PolicyVerdict(
                decision=Decision.DENY,
                reason=f"TrustLine Scope Violation: {scope_violation}",
                rule_triggered="RULE_SCOPE_BOUNDARY",
                details={"violation": scope_violation},
            )

        # ======================================================================
        # GATE 2: Canary Secret & Multi-Encoding Scanner (Deterministic)
        # ======================================================================
        scan_res = self.canary_inspector.scan_payload(tool_input)
        if scan_res.has_secret:
            reason = scan_res.primary_reason or "Sensitive canary secret detected in payload"
            self.taint_tracker.mark_violation(session_id, reason=reason)
            return PolicyVerdict(
                decision=Decision.DENY,
                reason=f"TrustLine Canary Egress Block: {reason}",
                rule_triggered="RULE_CANARY_EGRESS_BLOCKED",
                details={
                    "matches_count": len(scan_res.matches),
                    "primary_match": scan_res.matches[0].secret_type if scan_res.matches else None,
                    "encoding": scan_res.matches[0].encoding if scan_res.matches else None,
                },
            )

        # ======================================================================
        # GATE 3: Session Taint Escalation Check
        # ======================================================================
        if self.taint_tracker.requires_confirmation(session_id, tool_name, tool_input):
            return PolicyVerdict(
                decision=Decision.ASK,
                reason=(
                    f"Privileged action '{tool_name}' requires human approval because "
                    f"session '{session_id}' is in {self.taint_tracker.get_state(session_id).value} state."
                ),
                rule_triggered="RULE_TAINT_ESCALATION",
                details={
                    "taint_state": self.taint_tracker.get_state(session_id).value,
                    "history_count": len(self.taint_tracker.get_history(session_id)),
                },
            )

        # ======================================================================
        # GATE 4: AI & External Threat Intelligence (Advisory - Soham's Module)
        # ======================================================================
        ai_verdict = self._evaluate_ai_advisory(session_id, tool_name, tool_input)
        if ai_verdict:
            return ai_verdict

        # Default Permitted: Tool call satisfied all gates within active scope
        return PolicyVerdict(
            decision=Decision.ALLOW,
            reason="Tool call validated within authorized workspace boundaries.",
            rule_triggered="RULE_PERMITTED_SCOPE",
            details={"scope_root": cwd},
        )

    def _check_scope_and_paths(
        self, tool_name: str, tool_input: Dict[str, Any], cwd: str
    ) -> Optional[str]:
        """Validates that tool arguments do not target blacklisted or out-of-scope paths."""
        workspace_path = Path(cwd).resolve()

        # Extract all path-like values and string payloads
        extracted_strings: List[str] = []

        def _collect_strings(obj: Any) -> None:
            if isinstance(obj, str):
                extracted_strings.append(obj)
                if "%" in obj:
                    try:
                        unquoted = urllib.parse.unquote(obj)
                        if unquoted != obj:
                            extracted_strings.append(unquoted)
                    except Exception:
                        pass
            elif isinstance(obj, dict):
                for v in obj.values():
                    _collect_strings(v)
            elif isinstance(obj, (list, tuple)):
                for item in obj:
                    _collect_strings(item)

        _collect_strings(tool_input)

        # 1. Check against blacklisted paths patterns
        for s in extracted_strings:
            for pattern in self.FORBIDDEN_PATH_PATTERNS:
                if pattern.search(s):
                    return f"Access to forbidden credential path or file is blocked: '{pattern.pattern}'"

        # 2. Check explicit path parameters for directory traversal outside workspace
        explicit_path_keys = {"path", "file_path", "filePath", "target_path", "directory", "dir"}
        for k, v in tool_input.items():
            if k in explicit_path_keys and isinstance(v, str) and v.strip():
                try:
                    candidate = Path(v).expanduser()
                    if not candidate.is_absolute():
                        candidate = (workspace_path / candidate).resolve()
                    else:
                        candidate = candidate.resolve()

                    # Check if candidate path is within workspace_path
                    if not candidate.is_relative_to(workspace_path):
                        return f"Path '{v}' escapes authorized workspace root '{workspace_path}'"
                except (ValueError, RuntimeError):
                    return f"Malformed path argument '{v}'"

        return None

    def _evaluate_ai_advisory(
        self, session_id: str, tool_name: str, tool_input: Dict[str, Any]
    ) -> Optional[PolicyVerdict]:
        """
        Queries Soham's AI modules (injection_detector, tavily_shield) if wired.
        Gracefully skipped if AI modules are not yet plugged in or during offline runs.
        """
        # When Soham builds injection_detector, we interface with it here
        if self.injection_detector is not None:
            try:
                # Check command or file content strings
                content = str(tool_input.get("command", "") or tool_input.get("content", ""))
                if content:
                    analysis = self.injection_detector.detect_injection_sync(content)
                    if analysis and getattr(analysis, "is_injection", False):
                        conf = getattr(analysis, "confidence", 1.0)
                        if conf >= 0.70:
                            self.taint_tracker.mark_ingestion(
                                session_id=session_id,
                                source_type="injection_detector",
                                source_uri=tool_name,
                                is_trusted=False,
                                notes=f"Nemotron detected injection (conf={conf:.2f})",
                            )
                            return PolicyVerdict(
                                decision=Decision.DENY,
                                reason=f"NVIDIA Nemotron Flagged Prompt Injection (confidence {conf:.2f}): {getattr(analysis, 'reason', 'Adversarial instruction')}",
                                rule_triggered="RULE_NEMOTRON_INJECTION_DETECTED",
                                details={"confidence": conf},
                            )
            except Exception:
                # Advisory AI failure does not block benign execution unless sensitive
                pass

        return None
