"""
TrustLine - Multi-Encoding Canary & Secret Inspector
Owner: Pranjay (Team Lead & Cybersecurity Lead)

Ensures that private credentials, API tokens, and synthetic canary strings
are never transmitted outside the machine, even if LLM classifiers fail.
Recursively inspects payloads across Plaintext, Hex, Base64, and URL encodings.
"""

import base64
import binascii
import re
import secrets
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


@dataclass
class SecretMatch:
    """Represents an identified secret or canary in a payload."""
    secret_type: str
    encoding: str
    snippet: str
    rule_name: str


@dataclass
class ScanResult:
    """Overall outcome of a payload secret inspection."""
    has_secret: bool
    matches: List[SecretMatch] = field(default_factory=list)

    @property
    def primary_reason(self) -> Optional[str]:
        if not self.has_secret or not self.matches:
            return None
        first = self.matches[0]
        return f"Detected {first.secret_type} in {first.encoding} encoding ({first.rule_name})"


class CanaryInspector:
    """
    High-performance scanner that detects canary tokens and high-value developer
    secrets across multiple data representations (Plaintext, Base64, Hex, URL).
    """

    DEFAULT_CANARY_PREFIX = "CANARY-FIREWALL-SECRET"

    # Known high-value developer credential signatures
    SECRET_PATTERNS = {
        "AWS_ACCESS_KEY": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "GITHUB_PAT": re.compile(r"\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b"),
        "PRIVATE_KEY_HEADER": re.compile(
            r"-----BEGIN\s+(RSA|OPENSSH|EC|DSA|PGP)?\s*PRIVATE\s+KEY",
            re.IGNORECASE,
        ),
        "GENERIC_CANARY_PATTERN": re.compile(
            r"CANARY-(?:FIREWALL|TRUSTLINE)-SECRET-[A-Za-z0-9_-]+",
            re.IGNORECASE,
        ),
    }

    # Potential Base64 string pattern (minimum 16 characters)
    BASE64_PATTERN = re.compile(r"\b[A-Za-z0-9+/]{16,}={0,2}\b")
    # Potential Hex encoded pattern (even length, minimum 16 hex chars = 8 bytes)
    HEX_PATTERN = re.compile(r"\b(?:[0-9a-fA-F]{2}){8,}\b")

    def __init__(self, registered_canaries: Optional[Set[str]] = None):
        """
        Initialize inspector with an optional set of actively armed canary secrets.
        """
        self.registered_canaries: Set[str] = set(registered_canaries or [])

    def generate_canary(self, prefix: str = DEFAULT_CANARY_PREFIX) -> str:
        """
        Generates a cryptographically secure synthetic canary token,
        registers it, and returns the token string.
        """
        token = f"{prefix}-{secrets.token_hex(12).upper()}"
        self.registered_canaries.add(token)
        return token

    def arm_canary(self, canary: str) -> None:
        """Registers an existing canary token for monitoring."""
        if canary and isinstance(canary, str):
            self.registered_canaries.add(canary.strip())

    def clear_canaries(self) -> None:
        """Clears all armed canaries."""
        self.registered_canaries.clear()

    def scan_payload(self, payload: Any) -> ScanResult:
        """
        Recursively scans strings, dictionaries, lists, or tuples for secrets.
        """
        matches: List[SecretMatch] = []
        visited_ids: Set[int] = set()

        def _traverse(obj: Any) -> None:
            if obj is None:
                return
            obj_id = id(obj)
            if obj_id in visited_ids:
                return
            visited_ids.add(obj_id)

            if isinstance(obj, str):
                matches.extend(self._scan_text(obj))
            elif isinstance(obj, bytes):
                try:
                    decoded = obj.decode("utf-8", errors="ignore")
                    matches.extend(self._scan_text(decoded))
                except Exception:
                    pass
            elif isinstance(obj, dict):
                for k, v in obj.items():
                    _traverse(k)
                    _traverse(v)
            elif isinstance(obj, (list, tuple, set)):
                for item in obj:
                    _traverse(item)

        _traverse(payload)
        return ScanResult(has_secret=len(matches) > 0, matches=matches)

    def _scan_text(self, text: str) -> List[SecretMatch]:
        """
        Scans a single text string across Plaintext, URL-decoded, Base64, and Hex.
        """
        if not text:
            return []

        found_matches: List[SecretMatch] = []

        # 1. Plaintext scan
        found_matches.extend(self._scan_raw_buffer(text, encoding="PLAINTEXT"))

        # 2. URL-decoded scan (if URL encoding is present)
        if "%" in text:
            try:
                unquoted = urllib.parse.unquote(text)
                if unquoted != text:
                    found_matches.extend(self._scan_raw_buffer(unquoted, encoding="URL_DECODED"))
            except Exception:
                pass

        # 3. Base64 sub-string scan
        for b64_candidate in self.BASE64_PATTERN.findall(text):
            # Pad candidate if needed
            padded = b64_candidate
            missing_padding = len(padded) % 4
            if missing_padding:
                padded += "=" * (4 - missing_padding)

            try:
                decoded_bytes = base64.b64decode(padded, validate=True)
                # Ensure it's legible text (not random binary noise)
                decoded_text = decoded_bytes.decode("utf-8")
                matches = self._scan_raw_buffer(decoded_text, encoding="BASE64")
                found_matches.extend(matches)
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue

        # 4. Hex sub-string scan
        for hex_candidate in self.HEX_PATTERN.findall(text):
            try:
                decoded_bytes = bytes.fromhex(hex_candidate)
                decoded_text = decoded_bytes.decode("utf-8")
                matches = self._scan_raw_buffer(decoded_text, encoding="HEX")
                found_matches.extend(matches)
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue

        # Deduplicate matches by rule_name + encoding
        unique_matches: List[SecretMatch] = []
        seen = set()
        for m in found_matches:
            key = (m.rule_name, m.encoding, m.snippet)
            if key not in seen:
                seen.add(key)
                unique_matches.append(m)

        return unique_matches

    def _scan_raw_buffer(self, buffer: str, encoding: str) -> List[SecretMatch]:
        """
        Tests a decoded text buffer against active canaries and known secret patterns.
        """
        matches: List[SecretMatch] = []

        # Check explicitly registered active canaries
        for canary in self.registered_canaries:
            if canary in buffer:
                snippet = self._make_snippet(buffer, canary)
                matches.append(
                    SecretMatch(
                        secret_type="ARMED_CANARY_TOKEN",
                        encoding=encoding,
                        snippet=snippet,
                        rule_name="CANARY_EGRESS_RULE",
                    )
                )

        # Check regex credential patterns
        for rule_name, pattern in self.SECRET_PATTERNS.items():
            found = pattern.search(buffer)
            if found:
                match_val = found.group(0)
                snippet = self._make_snippet(buffer, match_val)
                matches.append(
                    SecretMatch(
                        secret_type=rule_name,
                        encoding=encoding,
                        snippet=snippet,
                        rule_name=f"RULE_{rule_name}",
                    )
                )

        return matches

    @staticmethod
    def _make_snippet(text: str, target: str, max_surround: int = 20) -> str:
        """Creates a masked, context-preserving preview snippet."""
        pos = text.find(target)
        if pos == -1:
            return target[:12] + "..."
        start = max(0, pos - max_surround)
        end = min(len(text), pos + len(target) + max_surround)
        prefix = "..." if start > 0 else ""
        suffix = "..." if end < len(text) else ""
        # Mask middle characters of the secret for safe logging
        if len(target) > 8:
            masked_target = target[:4] + "*" * (len(target) - 8) + target[-4:]
        else:
            masked_target = "***"
        snippet = prefix + text[start:pos] + masked_target + text[pos + len(target):end] + suffix
        return snippet.replace("\n", " ").replace("\r", " ")
