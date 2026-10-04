"""Early evidence hygiene; best-effort redaction is not a secrecy guarantee."""

import hashlib
import re
import unicodedata


def sanitize(text: str, limit: int = 4096) -> str:
    """Strip controls and redact common credentials before persistence."""
    text = "".join(
        " " if c in "\r\n\t" else c
        for c in text[:65536]
        if c in "\r\n\t" or not unicodedata.category(c).startswith("C")
    )

    def placeholder(match: re.Match[str]) -> str:
        """Create a stable irreversible placeholder for a matched value."""
        return "[REDACTED:" + hashlib.sha256(match.group().encode()).hexdigest()[:12] + "]"

    for pattern in (
        r"""(?i)["'](?:password|passwd|secret|token|api[_-]?key|authorization)["']\s*:\s*["'][^"']*["']""",
        r"""(?i)\b(?:password|passwd|secret|token|api[_-]?key|authorization)\s*[:=]\s*["'][^"']*["']""",
        r"(?i)\b(?:password|passwd|secret|token|api[_-]?key|authorization)\s*[:=]\s*[^\s,;]+",
        r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+",
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        r"\bsk-[A-Za-z0-9_-]{12,}\b",
    ):
        text = re.sub(pattern, placeholder, text)
    return text[:limit]
