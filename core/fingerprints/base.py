"""Abstract base class for WAF fingerprint detectors."""
from __future__ import annotations

from abc import ABC, abstractmethod

import httpx

from core.models import FingerprintResult, WAFSignal, WAFVendor


class BaseDetector(ABC):
    """
    Each WAF detector implements this interface.
    ``score`` analyses a response and returns a FingerprintResult
    with a confidence value built from matched signals.
    """

    MAX_CONFIDENCE = 1.0
    SIGNAL_WEIGHTS: dict[str, float] = {}   # defined per subclass

    @property
    @abstractmethod
    def vendor(self) -> WAFVendor: ...

    @abstractmethod
    def score(self, response: httpx.Response, body: str) -> FingerprintResult: ...

    # ── Helpers shared by all detectors ─────────────────────────────────────

    def _headers(self, response: httpx.Response) -> dict[str, str]:
        return {k.lower(): v for k, v in response.headers.items()}

    def _cookies(self, response: httpx.Response) -> dict[str, str]:
        return dict(response.cookies)

    def _clamp(self, value: float) -> float:
        return min(self.MAX_CONFIDENCE, max(0.0, value))

    def _build_result(
        self,
        signals: list[WAFSignal],
        response: httpx.Response,
    ) -> FingerprintResult:
        confidence = self._clamp(sum(s.weight for s in signals))
        return FingerprintResult(
            vendor=self.vendor,
            confidence=confidence,
            signals=signals,
            raw_headers=self._headers(response),
            status_code=response.status_code,
        )
