"""
Fingerprint orchestrator — runs all WAF detectors against a response
and returns a ranked list ordered by confidence score.
"""
from __future__ import annotations
import httpx
from core.models import FingerprintResult, WAFVendor
from core.fingerprints.base import BaseDetector
from core.fingerprints.cloudflare  import CloudflareDetector
from core.fingerprints.akamai      import AkamaiDetector
from core.fingerprints.modsecurity import ModSecurityDetector
from core.fingerprints.aws_waf     import AWSWAFDetector
from core.fingerprints.imperva     import ImpervaDetector
from core.fingerprints.f5_bigip    import F5BigIPDetector

CONFIDENCE_THRESHOLD = 0.25


class FingerprintOrchestrator:
    """
    Runs every registered detector and returns the best match.

    Usage::
        o = FingerprintOrchestrator()
        result = o.identify(response)
        print(result.vendor, result.confidence_pct)
    """

    _detectors: list[BaseDetector] = [
        CloudflareDetector(),
        AkamaiDetector(),
        ModSecurityDetector(),
        AWSWAFDetector(),
        ImpervaDetector(),
        F5BigIPDetector(),
    ]

    def identify(self, response: httpx.Response) -> FingerprintResult:
        """Return the highest-confidence detection result."""
        body    = self._body(response)
        results = sorted(
            [d.score(response, body) for d in self._detectors],
            key=lambda r: r.confidence, reverse=True,
        )
        best = results[0]
        if best.confidence < CONFIDENCE_THRESHOLD:
            return FingerprintResult(
                vendor=WAFVendor.NONE, confidence=0.0,
                raw_headers={k.lower(): v for k, v in response.headers.items()},
                status_code=response.status_code,
            )
        return best

    def identify_all(self, response: httpx.Response) -> list[FingerprintResult]:
        """Return every result ≥ threshold (supports layered WAFs)."""
        body = self._body(response)
        return sorted(
            [r for r in [d.score(response, body) for d in self._detectors]
             if r.confidence >= CONFIDENCE_THRESHOLD],
            key=lambda r: r.confidence, reverse=True,
        )

    @staticmethod
    def _body(r: httpx.Response, n: int = 8192) -> str:
        try: return r.text[:n]
        except Exception: return ""
