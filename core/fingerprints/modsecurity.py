"""ModSecurity / NAXSI fingerprint detector."""
from __future__ import annotations
import re
import httpx
from core.models import FingerprintResult, WAFSignal, WAFVendor
from core.fingerprints.base import BaseDetector


class ModSecurityDetector(BaseDetector):
    vendor = WAFVendor.MODSECURITY

    _SERVER    = re.compile(r"(mod_security|modsecurity|naxsi)", re.I)
    _HDR_MSGS  = {"x-mod-security-message", "x-modsec-rule"}
    _BODY      = re.compile(
        r"(mod_?security|modsecurity|naxsi|406\s+not\s+acceptable"
        r"|this\s+error\s+was\s+generated\s+by\s+mod_security"
        r"|web\s+application\s+firewall\s+block)", re.I | re.S
    )
    _STATUS    = {406, 403, 501}

    def score(self, response: httpx.Response, body: str) -> FingerprintResult:
        headers = self._headers(response)
        signals: list[WAFSignal] = []

        if self._SERVER.search(headers.get("server", "")):
            signals.append(WAFSignal("Server header matches ModSecurity/NAXSI", 0.55, "header"))

        for h in self._HDR_MSGS:
            if h in headers:
                signals.append(WAFSignal(f"ModSecurity header '{h}' present", 0.45, "header"))

        if response.status_code in self._STATUS:
            signals.append(WAFSignal(f"Status {response.status_code} typical of ModSecurity", 0.15, "status"))

        if self._BODY.search(body):
            signals.append(WAFSignal("ModSecurity block-page body pattern", 0.40, "body"))

        return self._build_result(signals, response)
