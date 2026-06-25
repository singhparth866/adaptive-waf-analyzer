"""AWS WAF fingerprint detector."""
from __future__ import annotations
import re
import httpx
from core.models import FingerprintResult, WAFSignal, WAFVendor
from core.fingerprints.base import BaseDetector


class AWSWAFDetector(BaseDetector):
    vendor = WAFVendor.AWS_WAF

    _AWS_HEADERS = {"x-amzn-requestid", "x-amzn-trace-id", "x-amz-cf-id", "x-amz-cf-pop"}
    _BODY = re.compile(
        r"(aws\s*waf|request\s+blocked|awswaf|403\s+forbidden.*amazon)", re.I | re.S
    )
    _SERVER = re.compile(r"(awselb|awsalb|amazon)", re.I)

    def score(self, response: httpx.Response, body: str) -> FingerprintResult:
        headers = self._headers(response)
        signals: list[WAFSignal] = []

        for h in self._AWS_HEADERS:
            if h in headers:
                signals.append(WAFSignal(f"AWS header '{h}' present", 0.35, "header"))

        if self._SERVER.search(headers.get("server", "")):
            signals.append(WAFSignal("Server header matches AWS infrastructure", 0.25, "header"))

        if response.status_code == 403 and signals:
            signals.append(WAFSignal("403 with AWS signals", 0.20, "status"))

        if self._BODY.search(body):
            signals.append(WAFSignal("AWS WAF block-page body pattern", 0.45, "body"))

        return self._build_result(signals, response)
