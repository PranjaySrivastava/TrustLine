"""
TrustLine - Claude Code PreToolUse Hook Adapter
Owner: Pranjay (Team Lead & Cybersecurity Lead)

Stdio adapter connecting Anthropic Claude Code CLI to the TrustLine Policy Engine.
Catches all tool calls via sys.stdin, evaluates them against deterministic zero-trust
boundaries, and returns structured permission decisions on sys.stdout.
Guarantees fail-closed security: any error defaults to 'deny'.
"""

import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from gateway.audit_logger import AuditLogger
from gateway.canary_inspector import CanaryInspector
from gateway.policy_engine import PolicyEngine, ToolCallRequest
from gateway.taint_tracker import SessionTaintTracker


# Global singleton instances for the CLI lifecycle
_INSPECTOR = CanaryInspector()
_TAINT_TRACKER = SessionTaintTracker()
_POLICY_ENGINE = PolicyEngine(
    canary_inspector=_INSPECTOR,
    taint_tracker=_TAINT_TRACKER,
)
_AUDIT_LOGGER = AuditLogger()


def make_response(
    decision: str,
    reason: str,
    hook_event_name: str = "PreToolUse",
) -> Dict[str, Any]:
    """Formats structured hook output matching Claude Code schema."""
    return {
        "hookSpecificOutput": {
            "hookEventName": hook_event_name,
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }


def process_hook_input(
    raw_input: str,
    policy_engine: Optional[PolicyEngine] = None,
    audit_logger: Optional[AuditLogger] = None,
) -> Dict[str, Any]:
    """
    Parses incoming PreToolUse JSON payload, evaluates against the policy engine,
    and returns Claude Code decision dictionary.
    """
    engine = policy_engine or _POLICY_ENGINE
    logger = audit_logger or _AUDIT_LOGGER

    if not raw_input or not raw_input.strip():
        return make_response("deny", "Empty hook payload received (fail closed)")

    try:
        data = json.loads(raw_input)
    except json.JSONDecodeError as exc:
        return make_response("deny", f"Malformed JSON in hook payload: {str(exc)} (fail closed)")

    hook_event = data.get("hookEventName", "PreToolUse")
    session_id = data.get("sessionId", "default")
    tool_name = data.get("toolName", "unknown")
    tool_input = data.get("toolInput", {})
    cwd = data.get("cwd")

    request = ToolCallRequest(
        session_id=session_id,
        tool_name=tool_name,
        tool_input=tool_input,
        cwd=cwd,
    )

    verdict = engine.evaluate(request)

    # Record in local audit trail
    arg_preview = str(tool_input)[:200]
    taint_state = engine.taint_tracker.get_state(session_id).value
    logger.log_event(
        tool_name=tool_name,
        decision=verdict.decision.value,
        rule_triggered=verdict.rule_triggered,
        reason=verdict.reason,
        session_id=session_id,
        arguments_preview=arg_preview,
        taint_state=taint_state,
    )

    return make_response(
        decision=verdict.decision.value,
        reason=verdict.reason,
        hook_event_name=hook_event,
    )


def main() -> None:
    """Entry point when executed by Claude Code CLI via stdio."""
    try:
        raw_payload = sys.stdin.read()
        response = process_hook_input(raw_payload)
        json.dump(response, sys.stdout)
        sys.stdout.flush()
    except Exception as exc:
        # Emergency fail-closed output
        fallback = make_response(
            decision="deny",
            reason=f"TrustLine Stdio Fatal Exception: {str(exc)} (fail closed)",
        )
        json.dump(fallback, sys.stdout)
        sys.stdout.flush()


if __name__ == "__main__":
    main()
