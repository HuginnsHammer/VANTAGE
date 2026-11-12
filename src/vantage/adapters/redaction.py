"""Best-effort secret redaction for scanner-controlled text.

This is a defense-in-depth sanitizer, not a complete data-loss-prevention control.
"""
from __future__ import annotations

import re

_SENSITIVE_KEY = (
    r"(?:api[_-]?key|access[_-]?key(?:[_-]?id)?|"
    r"secret(?:[_-]?(?:access[_-]?)?key)?|client[_-]?secret|"
    r"password|passwd|token|auth[_-]?token|access[_-]?token|"
    r"refresh[_-]?token|private[_-]?key)"
)
_QUOTED_SECRET = re.compile(
    rf"""(?ix)
    (?P<prefix>\b{_SENSITIVE_KEY}\b\s*[:=]\s*)
    (?P<quote>['"])
    (?P<value>(?:\\.|(?! (?P=quote) ).)*)
    (?P=quote)
    """
)
_UNQUOTED_SECRET = re.compile(
    rf"""(?ix)
    (?P<prefix>\b{_SENSITIVE_KEY}\b\s*[:=]\s*)
    (?P<value>(?!['"])[^\s,;#]+)
    """
)
_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?"
    r"-----END [A-Z0-9 ]*PRIVATE KEY-----"
)
_AWS_ACCESS_KEY = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_GITHUB_TOKEN = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b"
)
_JWT = re.compile(
    r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"
)
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")
_BASIC_AUTH = re.compile(
    r"(?i)(\bAuthorization\s*[:=]\s*Basic\s+)[A-Za-z0-9+/=]+"
)
_URL_PASSWORD = re.compile(
    r"(?i)(\b[a-z][a-z0-9+.-]*://[^:/@\s]+:)([^@\s/]+)(@)"
)


def _is_placeholder(value: str) -> bool:
    candidate = value.strip()
    lowered = candidate.lower()
    return (
        lowered in {"null", "none", "true", "false"}
        or candidate.startswith(("$", "${"))
        or lowered.startswith(("var.", "os.environ", "process.env"))
        or (candidate.startswith("<") and candidate.endswith(">"))
    )


def _redact_quoted(match: re.Match[str]) -> str:
    if _is_placeholder(match.group("value")):
        return match.group(0)
    return (
        f"{match.group('prefix')}{match.group('quote')}"
        "[REDACTED]"
        f"{match.group('quote')}"
    )


def _redact_unquoted(match: re.Match[str]) -> str:
    if _is_placeholder(match.group("value")):
        return match.group(0)
    return f"{match.group('prefix')}[REDACTED]"


def redact_sensitive_text(value: object) -> str:
    """Redact common credential formats while preserving surrounding context."""
    text = str(value)
    text = _QUOTED_SECRET.sub(_redact_quoted, text)
    text = _UNQUOTED_SECRET.sub(_redact_unquoted, text)
    text = _PRIVATE_KEY.sub("[REDACTED PRIVATE KEY]", text)
    text = _AWS_ACCESS_KEY.sub("[REDACTED AWS ACCESS KEY]", text)
    text = _GITHUB_TOKEN.sub("[REDACTED GITHUB TOKEN]", text)
    text = _JWT.sub("[REDACTED JWT]", text)
    text = _BEARER.sub("Bearer [REDACTED]", text)
    text = _BASIC_AUTH.sub(r"\1[REDACTED]", text)
    text = _URL_PASSWORD.sub(r"\1[REDACTED]\3", text)
    return text
