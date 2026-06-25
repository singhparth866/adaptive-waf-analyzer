"""
reports/json_report.py — Full structured JSON report writer.

Output schema
-------------
{
  "meta":       { tool, version, timestamp, target, mode, duration_sec },
  "fingerprint": { vendor, confidence, confidence_pct, signals, status_code },
  "statistics":  { total, blocked, allowed, challenged, filtered,
                   rate_limited, errors, block_rate_pct, avg_ms },
  "summary": {
    "mutation_breakdown":  { mutation_type: { total, blocked, allowed } },
    "category_breakdown":  { xss: {...}, sqli: {...} },
    "top_allowed_payloads": [ {payload, mutation, category, status_code} ],
    "top_blocked_payloads": [ {payload, mutation, category, status_code} ],
  },
  "probes": [ { payload, original, mutation, category,
                classification, status_code, resp_length,
                resp_time_ms, blocked, notes } ],
  "errors": [ ... ]
}
"""
from __future__ import annotations

import json
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

from core.models import ResponseClass, ScanResult


# ─────────────────────────────────────────────────────────────────────────────

def write(result: ScanResult, output_dir: str = "./reports") -> Path:
    """Serialise *result* to a timestamped JSON file and return its path."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    ts   = time.strftime("%Y%m%d_%H%M%S")
    slug = _slug(result.target)
    path = Path(output_dir) / f"waf_scan_{slug}_{ts}.json"

    data = _build(result)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def _build(result: ScanResult) -> dict[str, Any]:
    fp = result.fingerprint
    return {
        "meta": {
            "tool":         "WAF Fingerprinter & Bypass Analyzer",
            "version":      "1.0.0",
            "timestamp":    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "target":       result.target,
            "mode":         result.mode,
            "duration_sec": round(result.duration, 2),
        },
        "fingerprint": fp.to_dict() if fp else None,
        "statistics":  result.stats.to_dict(),
        "summary":     _build_summary(result),
        "probes":      [p.to_dict() for p in result.probes],
        "errors":      result.errors,
    }


def _build_summary(result: ScanResult) -> dict[str, Any]:
    """Aggregate breakdown tables useful for quick analysis."""
    probes = result.probes

    # ── Mutation-type breakdown ───────────────────────────────────────────────
    mut: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "blocked": 0, "allowed": 0, "challenged": 0, "filtered": 0})
    for p in probes:
        k = p.payload.kind.value
        mut[k]["total"] += 1
        c = p.classification.value.lower()
        if c in mut[k]:
            mut[k][c] += 1

    # ── Category breakdown ────────────────────────────────────────────────────
    cat: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "blocked": 0, "allowed": 0})
    for p in probes:
        k = p.payload.category.value
        cat[k]["total"] += 1
        if p.blocked:
            cat[k]["blocked"] += 1
        elif p.classification == ResponseClass.ALLOWED:
            cat[k]["allowed"] += 1

    # ── Top payloads ──────────────────────────────────────────────────────────
    allowed = [p for p in probes if p.classification == ResponseClass.ALLOWED]
    blocked = [p for p in probes if p.classification == ResponseClass.BLOCKED]

    def _fmt(lst, n=20):
        return [
            {
                "payload":    p.payload.value,
                "original":   p.payload.original,
                "mutation":   p.payload.kind.value,
                "category":   p.payload.category.value,
                "status_code": p.status_code,
                "resp_time_ms": round(p.resp_time * 1000, 1),
            }
            for p in lst[:n]
        ]

    return {
        "mutation_breakdown":   dict(mut),
        "category_breakdown":   dict(cat),
        "top_allowed_payloads": _fmt(allowed),
        "top_blocked_payloads": _fmt(blocked),
        "total_allowed":        len(allowed),
        "total_blocked":        len(blocked),
    }


def _slug(url: str) -> str:
    return (url.replace("https://", "")
               .replace("http://", "")
               .replace("/", "_")
               .replace(":", "_")
               .strip("_")[:50])
