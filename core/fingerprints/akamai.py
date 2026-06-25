"""Akamai Kona Site Defender / Bot Manager fingerprint detector."""
from __future__ import annotations
import re
import httpx
from core.models import FingerprintResult, WAFSignal, WAFVendor
from core.fingerprints.base import BaseDetector


class AkamaiDetector(BaseDetector):
    vendor = WAFVendor.AKAMAI

    _HDR_DEFINITIVE = {"x-akamai-request-id", "x-akamai-transformed", "akamai-origin-hop",
                       "x-check-cacheable", "x-akamai-ssl-client-sid"}
    _BM_COOKIES     = re.compile(r"^(ak_bmsc|bm_sv|bm_sz|bm_mi)$", re.I)
    _BODY           = re.compile(
        r"(akamai|reference\s+#\s*[\d.]+|access\s+denied.*akamai|ghost)", re.I | re.S
    )

    def score(self, response: httpx.Response, body: str) -> FingerprintResult:
        headers = self._headers(response)
        cookies = self._cookies(response)
        signals: list[WAFSignal] = []

        for h in self._HDR_DEFINITIVE:
            if h in headers:
                signals.append(WAFSignal(f"Akamai header '{h}' present", 0.50, "header"))
                break

        if "x-cache" in headers and "akamai" in headers["x-cache"].lower():
            signals.append(WAFSignal("X-Cache contains 'akamai'", 0.35, "header"))

        if response.status_code in (403, 503) and signals:
            signals.append(WAFSignal(f"Status {response.status_code} with Akamai signals", 0.10, "status"))

        for name in cookies:
            if self._BM_COOKIES.match(name):
                signals.append(WAFSignal(f"Akamai Bot Manager cookie '{name}'", 0.40, "cookie"))
                break

        if self._BODY.search(body):
            signals.append(WAFSignal("Akamai block-page body pattern", 0.30, "body"))

        return self._build_result(signals, response)
