"""
Response analyzer — classifies a raw httpx response into a ResponseClass
and extracts WAF-relevant signals from headers, body, and status code.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

import httpx

from core.models import ResponseClass


# ── Classification rules ──────────────────────────────────────────────────────

# Status codes that definitively indicate blocking / challenges
_BLOCK_CODES   = {403, 406, 501}
_CHALLENGE_CODES = {429, 503}
_RATE_LIMIT_CODES = {429, 503}

# Body patterns that indicate a block page regardless of status code
_BLOCK_BODY = re.compile(
    r'(access\s+denied|request\s+blocked|blocked\s+by|'
    r'security\s+violation|attack\s+detected|'
    r'forbidden.*firewall|your\s+ip\s+has\s+been\s+blocked|'
    r'suspicious\s+activity)',
    re.I | re.S,
)

# Patterns indicating a CAPTCHA / JS challenge page
_CHALLENGE_BODY = re.compile(
    r'(captcha|challenge|are\s+you\s+human|'
    r'verify\s+you\s+are|ddos\s+protection|'
    r'checking\s+your\s+browser|just\s+a\s+moment)',
    re.I | re.S,
)

# Patterns indicating silent response mutation (payload stripped but 200 returned)
_FILTER_SIGNALS = re.compile(
    r'(script\s+removed|content\s+filtered|tag\s+stripped|'
    r'input\s+sanitized)',
    re.I | re.S,
)

# Headers injected by WAFs to mark a request as blocked/filtered
_BLOCK_HEADERS = {
    "x-blocked-by", "x-waf-action", "x-firewall-block",
    "x-security-block", "x-denied-reason",
}


# ── Result object ──────────────────────────────────────────────────────────────

@dataclass
class AnalysisResult:
    classification: ResponseClass
    status_code: int
    resp_length: int
    resp_time: float               # seconds
    blocked: bool
    signals: list[str] = field(default_factory=list)
    resp_headers: dict[str, str] = field(default_factory=dict)


# ── Analyser ─────────────────────────────────────────────────────────────────

class ResponseAnalyzer:
    """
    Stateless analyser.  Optionally accepts a *baseline_length* (from a
    clean request) to detect silent filtering by comparing response sizes.
    """

    def __init__(self, baseline_length: int = 0, length_threshold: float = 0.20):
        self._baseline = baseline_length
        self._threshold = length_threshold

    def analyse(self, response: httpx.Response, elapsed: float) -> AnalysisResult:
        headers  = {k.lower(): v for k, v in response.headers.items()}
        body     = self._safe_body(response)
        status   = response.status_code
        length   = len(response.content)
        signals: list[str] = []

        # ── Status-code based ────────────────────────────────────────────────
        if status in _BLOCK_CODES:
            signals.append(f"Block status code: {status}")
        if status in _CHALLENGE_CODES:
            signals.append(f"Challenge/rate-limit status code: {status}")

        # ── Header based ─────────────────────────────────────────────────────
        for h in _BLOCK_HEADERS:
            if h in headers:
                signals.append(f"Block header present: {h}")

        # ── Body pattern based ────────────────────────────────────────────────
        if _BLOCK_BODY.search(body):
            signals.append("Block-page body pattern matched")
        if _CHALLENGE_BODY.search(body):
            signals.append("CAPTCHA/challenge page body pattern matched")
        if _FILTER_SIGNALS.search(body):
            signals.append("Silent-filter body pattern matched")

        # ── Length delta (silent filtering) ──────────────────────────────────
        if self._baseline > 0:
            delta = abs(length - self._baseline) / max(self._baseline, 1)
            if delta > self._threshold:
                signals.append(
                    f"Response length changed by {delta * 100:.1f}% vs baseline"
                )

        # ── Derive classification ────────────────────────────────────────────
        cls = self._classify(status, body, signals)
        blocked = cls in (ResponseClass.BLOCKED, ResponseClass.CHALLENGED)

        return AnalysisResult(
            classification=cls,
            status_code=status,
            resp_length=length,
            resp_time=elapsed,
            blocked=blocked,
            signals=signals,
            resp_headers=headers,
        )

    # ── Private helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _classify(
        status: int, body: str, signals: list[str]
    ) -> ResponseClass:
        """Derive a ResponseClass from the collected signals."""
        sig_text = " ".join(signals).lower()

        if status in _BLOCK_CODES or "block" in sig_text:
            if "captcha" in sig_text or "challenge" in sig_text:
                return ResponseClass.CHALLENGED
            return ResponseClass.BLOCKED

        if "captcha" in body.lower() or "challenge" in sig_text:
            return ResponseClass.CHALLENGED

        if status in _RATE_LIMIT_CODES or "rate-limit" in sig_text:
            return ResponseClass.RATE_LIMITED

        if "filter" in sig_text or "length changed" in sig_text:
            return ResponseClass.FILTERED

        if status >= 500:
            return ResponseClass.ERROR

        return ResponseClass.ALLOWED

    @staticmethod
    def _safe_body(response: httpx.Response, max_bytes: int = 8192) -> str:
        try:
            return response.text[:max_bytes]
        except Exception:
            return ""
