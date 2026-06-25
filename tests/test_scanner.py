"""
tests/test_scanner.py — Unit tests for engine/scanner.py
All network calls are mocked; no real HTTP requests are made.
"""
from __future__ import annotations
import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock
import pytest

from core.config import Config
from core.models import (
    FingerprintResult, MutatedPayload, MutationKind, PayloadKind,
    ProbeResult, ResponseClass, ScanResult, WAFVendor,
)
from engine.scanner import Scanner, _compute_stats, _inject, _join


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _cfg(**kwargs) -> Config:
    defaults = dict(mode="normal", concurrency=5, timeout=5.0,
                    max_retries=1, verbose=False, rate_limit=0.0,
                    baseline_count=1, test_payloads=True,
                    max_payloads=0, inject_param="q",
                    fingerprint_path="/", verify_ssl=False)
    defaults.update(kwargs)
    return Config.from_dict(defaults)


def _mock_response(status=200, body="", headers=None, content=None):
    r = MagicMock()
    r.status_code = status
    r.text        = body
    r.headers     = headers or {}
    r.content     = content or body.encode()
    r.cookies     = {}
    return r


def _payload(val="<script>alert(1)</script>") -> MutatedPayload:
    return MutatedPayload(
        value=val, kind=MutationKind.ORIGINAL,
        original=val, category=PayloadKind.XSS,
    )


# ── _join / _inject helpers ───────────────────────────────────────────────────

class TestHelpers:
    def test_join_no_trailing_slash(self):
        assert _join("https://example.com", "/") == "https://example.com/"

    def test_join_strips_double_slash(self):
        result = _join("https://example.com/", "/robots.txt")
        assert "example.com/robots.txt" in result

    def test_inject_adds_query_param(self):
        result = _inject("https://example.com", "q", "<script>")
        assert "q=" in result
        assert "example.com" in result

    def test_inject_uses_ampersand_when_query_exists(self):
        result = _inject("https://example.com?foo=bar", "q", "test")
        assert result.startswith("https://example.com?foo=bar&")


# ── _compute_stats ────────────────────────────────────────────────────────────

class TestComputeStats:
    def _probe(self, cls: ResponseClass, t=0.1) -> ProbeResult:
        p = MagicMock()
        p.classification = cls
        p.resp_time      = t
        p.blocked        = cls == ResponseClass.BLOCKED
        return p

    def test_counts_correctly(self):
        probes = [
            self._probe(ResponseClass.BLOCKED,      0.1),
            self._probe(ResponseClass.BLOCKED,      0.2),
            self._probe(ResponseClass.ALLOWED,      0.1),
            self._probe(ResponseClass.CHALLENGED,   0.3),
            self._probe(ResponseClass.FILTERED,     0.1),
            self._probe(ResponseClass.RATE_LIMITED, 0.1),
            self._probe(ResponseClass.ERROR,        0.5),
        ]
        s = _compute_stats(probes)
        assert s.total        == 7
        assert s.blocked      == 2
        assert s.allowed      == 1
        assert s.challenged   == 1
        assert s.filtered     == 1
        assert s.rate_limited == 1
        assert s.errors       == 1

    def test_block_rate(self):
        probes = [self._probe(ResponseClass.BLOCKED)] * 3 + \
                 [self._probe(ResponseClass.ALLOWED)] * 7
        s = _compute_stats(probes)
        assert s.block_rate == pytest.approx(0.3)

    def test_empty_probes(self):
        s = _compute_stats([])
        assert s.total == 0
        assert s.avg_ms == 0.0

    def test_avg_ms_calculated(self):
        probes = [self._probe(ResponseClass.ALLOWED, 0.1),
                  self._probe(ResponseClass.ALLOWED, 0.3)]
        s = _compute_stats(probes)
        assert s.avg_ms == pytest.approx(200.0)


# ── Scanner integration (mocked Dispatcher) ───────────────────────────────────

class TestScannerRun:
    """Full scanner.run() tests with Dispatcher mocked."""

    def _make_dispatcher_mock(self, responses: list):
        """Return a mock Dispatcher that yields responses in order."""
        disp   = AsyncMock()
        call_n = {"n": 0}

        async def fake_get(url, **kwargs):
            idx  = min(call_n["n"], len(responses) - 1)
            resp = responses[idx]
            call_n["n"] += 1
            return resp, 0.05

        disp.get            = fake_get
        disp.__aenter__     = AsyncMock(return_value=disp)
        disp.__aexit__      = AsyncMock(return_value=False)
        return disp

    @pytest.mark.asyncio
    async def test_passive_mode_no_probes(self):
        cfg = _cfg(mode="passive")
        resp = _mock_response(200, "", {"server": "nginx"})

        with patch("engine.scanner.Dispatcher") as MockDisp:
            MockDisp.return_value.__aenter__ = AsyncMock(
                return_value=self._make_dispatcher_mock([resp])
            )
            MockDisp.return_value.__aexit__ = AsyncMock(return_value=False)

            scanner = Scanner(cfg)
            with patch.object(scanner._orch, "identify_all", return_value=[]) as mock_ia, \
                 patch.object(scanner._orch, "identify",
                              return_value=FingerprintResult(
                                  vendor=WAFVendor.NONE, confidence=0.0, status_code=200)):
                result = await scanner.run("https://example.com", [])

        assert result.probes == []
        assert result.fingerprint is not None

    @pytest.mark.asyncio
    async def test_scan_result_has_correct_target(self):
        cfg  = _cfg(mode="passive")
        resp = _mock_response(200)

        with patch("engine.scanner.Dispatcher") as MockDisp:
            disp = self._make_dispatcher_mock([resp])
            MockDisp.return_value.__aenter__ = AsyncMock(return_value=disp)
            MockDisp.return_value.__aexit__  = AsyncMock(return_value=False)

            scanner = Scanner(cfg)
            with patch.object(scanner._orch, "identify_all", return_value=[]), \
                 patch.object(scanner._orch, "identify",
                              return_value=FingerprintResult(
                                  vendor=WAFVendor.NONE, confidence=0.0)):
                result = await scanner.run("https://target.example.com", [])

        assert result.target == "https://target.example.com"
        assert result.mode   == "passive"

    @pytest.mark.asyncio
    async def test_probe_errors_dont_abort_scan(self):
        """A probe that raises should produce an ERROR ProbeResult, not crash the scan."""
        import httpx
        cfg   = _cfg(mode="normal", baseline_count=1)
        base  = _mock_response(200)
        error = _mock_response(0)  # simulates connection error

        with patch("engine.scanner.Dispatcher") as MockDisp:
            disp = AsyncMock()
            call_n = {"n": 0}

            async def get_side_effect(url, **kw):
                call_n["n"] += 1
                if call_n["n"] == 1:
                    return base, 0.05       # baseline probe succeeds
                raise httpx.ConnectError("refused")

            disp.get        = get_side_effect
            disp.__aenter__ = AsyncMock(return_value=disp)
            disp.__aexit__  = AsyncMock(return_value=False)
            MockDisp.return_value = disp

            scanner = Scanner(cfg)
            fp_ok = FingerprintResult(vendor=WAFVendor.CLOUDFLARE, confidence=0.8,
                                      status_code=200)
            with patch.object(scanner._orch, "identify_all", return_value=[fp_ok]), \
                 patch.object(scanner._orch, "identify",     return_value=fp_ok):
                result = await scanner.run(
                    "https://example.com",
                    [_payload("<bad>"), _payload("' OR 1=1--")],
                )

        # Probes ran; errors turned into ERROR classification, scan didn't abort
        assert result is not None
        for p in result.probes:
            assert p.classification == ResponseClass.ERROR

    @pytest.mark.asyncio
    async def test_scan_duration_is_positive(self):
        cfg  = _cfg(mode="passive")
        resp = _mock_response(200)

        with patch("engine.scanner.Dispatcher") as MockDisp:
            disp = self._make_dispatcher_mock([resp])
            MockDisp.return_value.__aenter__ = AsyncMock(return_value=disp)
            MockDisp.return_value.__aexit__  = AsyncMock(return_value=False)
            scanner = Scanner(cfg)
            with patch.object(scanner._orch, "identify_all", return_value=[]), \
                 patch.object(scanner._orch, "identify",
                              return_value=FingerprintResult(
                                  vendor=WAFVendor.NONE, confidence=0.0)):
                result = await scanner.run("https://example.com", [])

        assert result.duration > 0

    @pytest.mark.asyncio
    async def test_on_probe_callback_fires(self):
        cfg     = _cfg(mode="normal", baseline_count=1)
        base    = _mock_response(200)
        blocked = _mock_response(403, "Access Denied")
        fired: list[ProbeResult] = []

        with patch("engine.scanner.Dispatcher") as MockDisp:
            disp = AsyncMock()
            call_n = {"n": 0}

            async def get_se(url, **kw):
                call_n["n"] += 1
                if call_n["n"] == 1: return base, 0.05
                return blocked, 0.05

            disp.get        = get_se
            disp.__aenter__ = AsyncMock(return_value=disp)
            disp.__aexit__  = AsyncMock(return_value=False)
            MockDisp.return_value = disp

            scanner = Scanner(cfg, on_probe=fired.append)
            fp      = FingerprintResult(vendor=WAFVendor.CLOUDFLARE, confidence=0.9,
                                        status_code=200)
            with patch.object(scanner._orch, "identify_all", return_value=[fp]), \
                 patch.object(scanner._orch, "identify",     return_value=fp):
                result = await scanner.run("https://example.com", [_payload()])

        assert len(fired) == len(result.probes)


# ── Scanner stats roundtrip ───────────────────────────────────────────────────

class TestScanResultToDict:
    def test_to_dict_includes_all_keys(self):
        result = ScanResult(
            target="https://example.com",
            mode="normal",
            fingerprint=FingerprintResult(
                vendor=WAFVendor.CLOUDFLARE, confidence=0.85, status_code=403
            ),
        )
        result.ended_at = result.started_at + 5.0
        d = result.to_dict()
        assert "target"      in d
        assert "mode"        in d
        assert "fingerprint" in d
        assert "stats"       in d
        assert "probes"      in d
        assert "errors"      in d
        assert "duration_sec" in d
        assert d["duration_sec"] == pytest.approx(5.0)

    def test_fingerprint_none_serialises(self):
        result = ScanResult(target="https://x.com", mode="passive", fingerprint=None)
        result.ended_at = result.started_at
        d = result.to_dict()
        assert d["fingerprint"] is None
