"""F5 BIG-IP ASM fingerprint detector."""
from __future__ import annotations
import re
import httpx
from core.models import FingerprintResult, WAFSignal, WAFVendor
from core.fingerprints.base import BaseDetector


class F5BigIPDetector(BaseDetector):
    vendor = WAFVendor.F5_BIGIP

    _HDR_DEFINITIVE = {"x-cnection", "x-wa-info", "x-forwarded-for"}
    _COOKIE_TS = re.compile(r"^TS[0-9a-f]{8}$", re.I)
    _BODY = re.compile(
        r"(bigip|big-ip|f5\s+networks|the\s+requested\s+url\s+was\s+rejected"
        r"|support\s+id\s*:\s*\d+)", re.I | re.S
    )
    _SERVER = re.compile(r"(bigip|big-ip)", re.I)

    def score(self, response: httpx.Response, body: str) -> FingerprintResult:
        headers = self._headers(response)
        cookies = self._cookies(response)
        signals: list[WAFSignal] = []

        if "x-wa-info" in headers:
            signals.append(WAFSignal("X-WA-Info header (F5 BIG-IP specific)", 0.60, "header"))

        if "x-cnection" in headers:
            signals.append(WAFSignal("X-Cnection header (F5 BIG-IP specific)", 0.50, "header"))

        if self._SERVER.search(headers.get("server", "")):
            signals.append(WAFSignal("Server header matches BIG-IP", 0.40, "header"))

        for name in cookies:
            if self._COOKIE_TS.match(name):
                signals.append(WAFSignal(f"F5 BIG-IP persistence cookie '{name}'", 0.45, "cookie"))
                break

        if response.status_code in (403, 501) and signals:
            signals.append(WAFSignal(f"Status {response.status_code} with F5 signals", 0.10, "status"))

        if self._BODY.search(body):
            signals.append(WAFSignal("F5 BIG-IP block-page body pattern", 0.40, "body"))

        return self._build_result(signals, response)
