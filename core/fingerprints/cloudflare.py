"""Cloudflare WAF fingerprint detector."""
from __future__ import annotations
import re
import httpx
from core.models import FingerprintResult, WAFSignal, WAFVendor
from core.fingerprints.base import BaseDetector


class CloudflareDetector(BaseDetector):
    vendor = WAFVendor.CLOUDFLARE

    # Definitive headers emitted by Cloudflare infrastructure
    _CF_HEADERS = {"cf-ray", "cf-cache-status", "cf-request-id", "cf-mitigated"}
    _CF_SERVER   = re.compile(r"cloudflare", re.I)
    _CF_COOKIES  = {"__cfduid", "cf_clearance", "__cf_bm"}
    _CF_BODY     = re.compile(
        r"(cloudflare|ray\s*id\s*[:·]\s*[0-9a-f]{16}|attention\s+required.*cloudflare)",
        re.I | re.S,
    )

    def score(self, response: httpx.Response, body: str) -> FingerprintResult:
        headers = self._headers(response)
        cookies = self._cookies(response)
        signals: list[WAFSignal] = []

        # ── CF-Ray (near-definitive) ─────────────────────────────────────────
        if "cf-ray" in headers:
            signals.append(WAFSignal("CF-Ray header present", 0.60, "header"))

        # ── Other CF-prefixed headers ────────────────────────────────────────
        for h in ("cf-cache-status", "cf-request-id", "cf-mitigated"):
            if h in headers:
                signals.append(WAFSignal(f"Header '{h}' present", 0.20, "header"))
                break  # count once

        # ── Server: cloudflare ────────────────────────────────────────────────
        if self._CF_SERVER.search(headers.get("server", "")):
            signals.append(WAFSignal("Server header matches 'cloudflare'", 0.30, "header"))

        # ── Block-status codes combined with CF patterns ─────────────────────
        if response.status_code in (403, 503, 429) and signals:
            signals.append(WAFSignal(
                f"Status {response.status_code} with Cloudflare signals", 0.10, "status"
            ))

        # ── Cookies ──────────────────────────────────────────────────────────
        for ck in self._CF_COOKIES:
            if ck in cookies:
                signals.append(WAFSignal(f"Cookie '{ck}' present", 0.25, "cookie"))
                break

        # ── Block-page body ───────────────────────────────────────────────────
        if self._CF_BODY.search(body):
            signals.append(WAFSignal("Cloudflare block-page body pattern matched", 0.35, "body"))

        return self._build_result(signals, response)
