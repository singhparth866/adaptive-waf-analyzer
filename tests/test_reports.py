"""
tests/test_reports.py — Unit tests for JSON and HTML report writers.
All tests use in-memory ScanResult objects; no real files are written
to unexpected locations.
"""
from __future__ import annotations
import json
import time
import tempfile
from pathlib import Path

import pytest

from core.models import (
    FingerprintResult, MutatedPayload, MutationKind,
    PayloadKind, ProbeResult, ResponseClass,
    ScanResult, ScanStats, WAFSignal, WAFVendor,
)
from reports import json_report, html_report


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _payload(val: str, kind=MutationKind.ORIGINAL, cat=PayloadKind.XSS) -> MutatedPayload:
    return MutatedPayload(value=val, kind=kind, original=val, category=cat)


def _probe(
    payload: MutatedPayload,
    cls: ResponseClass = ResponseClass.BLOCKED,
    status: int = 403,
    length: int = 512,
    rt: float = 0.12,
) -> ProbeResult:
    return ProbeResult(
        payload=payload,
        classification=cls,
        status_code=status,
        resp_length=length,
        resp_time=rt,
        blocked=(cls == ResponseClass.BLOCKED),
        resp_headers={},
        notes="test signal",
    )


def _full_result(n_blocked=3, n_allowed=2) -> ScanResult:
    fp = FingerprintResult(
        vendor=WAFVendor.CLOUDFLARE,
        confidence=0.92,
        signals=[
            WAFSignal("CF-Ray header present", 0.60, "header"),
            WAFSignal("Server header matches 'cloudflare'", 0.30, "header"),
        ],
        raw_headers={"cf-ray": "abc123", "server": "cloudflare"},
        status_code=403,
    )
    probes = (
        [_probe(_payload(f"<script>{i}</script>"), ResponseClass.BLOCKED, 403)
         for i in range(n_blocked)]
        +
        [_probe(_payload(f"<img src={i}>"), ResponseClass.ALLOWED, 200)
         for i in range(n_allowed)]
    )
    s = ScanResult(
        target="https://example.com",
        mode="normal",
        fingerprint=fp,
        probes=probes,
        errors=["example error"],
        started_at=time.time() - 10.0,
    )
    s.ended_at = time.time()
    s.stats    = ScanStats(
        total=n_blocked + n_allowed,
        blocked=n_blocked,
        allowed=n_allowed,
        avg_ms=120.0,
    )
    return s


# ── JSON report ───────────────────────────────────────────────────────────────

class TestJsonReport:
    def test_write_creates_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = _full_result()
            path   = json_report.write(result, tmp)
            assert path.exists()
            assert path.suffix == ".json"

    def test_file_is_valid_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = _full_result()
            path   = json_report.write(result, tmp)
            data   = json.loads(path.read_text())
            assert isinstance(data, dict)

    def test_meta_section_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = json.loads(json_report.write(_full_result(), tmp).read_text())
            assert "meta" in data
            assert data["meta"]["tool"] == "WAF Fingerprinter & Bypass Analyzer"
            assert "timestamp" in data["meta"]
            assert data["meta"]["target"] == "https://example.com"

    def test_fingerprint_section(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = json.loads(json_report.write(_full_result(), tmp).read_text())
            fp   = data["fingerprint"]
            assert fp["vendor"]  == "Cloudflare"
            assert fp["confidence"] == pytest.approx(0.92, abs=0.01)
            assert len(fp["signals"]) == 2

    def test_statistics_section(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = json.loads(json_report.write(_full_result(3, 2), tmp).read_text())
            s    = data["statistics"]
            assert s["total"]   == 5
            assert s["blocked"] == 3
            assert s["allowed"] == 2

    def test_summary_breakdown_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = json.loads(json_report.write(_full_result(), tmp).read_text())
            summ = data["summary"]
            assert "mutation_breakdown"   in summ
            assert "category_breakdown"   in summ
            assert "top_allowed_payloads" in summ
            assert "top_blocked_payloads" in summ

    def test_top_allowed_payloads_accurate(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = _full_result(n_blocked=1, n_allowed=3)
            data   = json.loads(json_report.write(result, tmp).read_text())
            allowed = data["summary"]["top_allowed_payloads"]
            assert len(allowed) == 3
            assert all("payload" in p for p in allowed)

    def test_probes_array_serialised(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = _full_result(2, 2)
            data   = json.loads(json_report.write(result, tmp).read_text())
            assert len(data["probes"]) == 4
            for p in data["probes"]:
                assert "payload"        in p
                assert "classification" in p
                assert "status_code"    in p
                assert "blocked"        in p

    def test_errors_included(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = json.loads(json_report.write(_full_result(), tmp).read_text())
            assert "example error" in data["errors"]

    def test_no_fingerprint_serialises(self):
        result = ScanResult(target="https://x.com", mode="passive", fingerprint=None)
        result.ended_at = result.started_at
        with tempfile.TemporaryDirectory() as tmp:
            data = json.loads(json_report.write(result, tmp).read_text())
            assert data["fingerprint"] is None

    def test_creates_output_dir_if_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            nested = str(Path(tmp) / "deep" / "nested")
            path   = json_report.write(_full_result(), nested)
            assert path.exists()

    def test_filename_contains_host(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = json_report.write(_full_result(), tmp)
            assert "example.com" in path.name

    def test_mutation_breakdown_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = _full_result()
            # add a double-encoded probe
            result.probes.append(
                _probe(_payload("test", MutationKind.DOUBLE_ENCODE), ResponseClass.ALLOWED, 200)
            )
            data   = json.loads(json_report.write(result, tmp).read_text())
            keys   = set(data["summary"]["mutation_breakdown"].keys())
            assert MutationKind.ORIGINAL.value in keys
            assert MutationKind.DOUBLE_ENCODE.value in keys


# ── HTML report ───────────────────────────────────────────────────────────────

class TestHtmlReport:
    def test_write_creates_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = html_report.write(_full_result(), tmp)
            assert path.exists()
            assert path.suffix == ".html"

    def test_file_is_nonempty(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = html_report.write(_full_result(), tmp)
            assert path.stat().st_size > 2000

    def test_html_doctype_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            content = html_report.write(_full_result(), tmp).read_text()
            assert "<!DOCTYPE html>" in content

    def test_vendor_name_in_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            content = html_report.write(_full_result(), tmp).read_text()
            assert "Cloudflare" in content

    def test_target_url_in_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            content = html_report.write(_full_result(), tmp).read_text()
            assert "example.com" in content

    def test_no_xss_in_escaped_payload(self):
        """Payload strings must be HTML-escaped so they can't break the report."""
        result = _full_result()
        result.probes.append(
            _probe(_payload("<script>alert('xss')</script>"), ResponseClass.ALLOWED, 200)
        )
        with tempfile.TemporaryDirectory() as tmp:
            content = html_report.write(result, tmp).read_text()
            # Raw unescaped tag must not appear verbatim
            assert "<script>alert(" not in content
            # Escaped version should appear
            assert "&lt;script&gt;" in content

    def test_error_section_when_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            content = html_report.write(_full_result(), tmp).read_text()
            assert "example error" in content

    def test_passive_mode_no_probe_table(self):
        result = ScanResult(target="https://x.com", mode="passive",
                            fingerprint=FingerprintResult(vendor=WAFVendor.NONE,
                                                          confidence=0.0))
        result.ended_at = result.started_at
        with tempfile.TemporaryDirectory() as tmp:
            content = html_report.write(result, tmp).read_text()
            assert "passive" in content.lower() or "no payload" in content.lower()

    def test_sortable_table_js_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            content = html_report.write(_full_result(), tmp).read_text()
            assert "data-sort" in content

    def test_css_variables_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            content = html_report.write(_full_result(), tmp).read_text()
            assert "--accent" in content
            assert "--bg"     in content

    def test_stat_grid_shows_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            result  = _full_result(n_blocked=7, n_allowed=3)
            content = html_report.write(result, tmp).read_text()
            assert "7" in content
            assert "3" in content
