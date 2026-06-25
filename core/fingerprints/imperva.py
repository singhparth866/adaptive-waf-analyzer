"""Imperva / Incapsula fingerprint detector."""
from __future__ import annotations
import re
import httpx
from core.models import FingerprintResult, WAFSignal, WAFVendor
from core.fingerprints.base import BaseDetector


class ImpervaDetector(BaseDetector):
    vendor = WAFVendor.IMPERVA

    _HDR_DEFINITIVE = {"x-iinfo", "x-cdn"}
    _COOKIES = re.compile(r"^(incap_ses_|visid_incap_|nlbi_)", re.I)
    _BODY = re.compile(
        r"(incapsula|imperva|request\s+unsuccessful|_iub_cs-|incap_ses)", re.I | re.S
    )

    def score(self, response: httpx.Response, body: str) -> FingerprintResult:
        headers = self._headers(response)
        cookies = self._cookies(response)
        signals: list[WAFSignal] = []

        if "x-iinfo" in headers:
            signals.append(WAFSignal("X-Iinfo header (Imperva-specific)", 0.65, "header"))

        cdn = headers.get("x-cdn", "")
        if "incapsula" in cdn.lower() or "imperva" in cdn.lower():
            signals.append(WAFSignal("X-CDN header identifies Incapsula/Imperva", 0.55, "header"))

        for name in cookies:
            if self._COOKIES.match(name):
                signals.append(WAFSignal(f"Imperva/Incapsula cookie '{name}'", 0.50, "cookie"))
                break

        if self._BODY.search(body):
            signals.append(WAFSignal("Imperva block-page body pattern", 0.35, "body"))

        return self._build_result(signals, response)
