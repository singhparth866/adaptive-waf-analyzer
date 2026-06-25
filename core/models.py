"""
Shared data models — used across fingerprints, mutations, analyzers, and reports.
"""
from __future__ import annotations
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class WAFVendor(str, Enum):
    CLOUDFLARE  = "Cloudflare"
    AKAMAI      = "Akamai"
    MODSECURITY = "ModSecurity"
    AWS_WAF     = "AWS WAF"
    IMPERVA     = "Imperva"
    F5_BIGIP    = "F5 BIG-IP"
    UNKNOWN     = "Unknown"
    NONE        = "None Detected"


class ResponseClass(str, Enum):
    ALLOWED      = "Allowed"
    BLOCKED      = "Blocked"
    CHALLENGED   = "Challenged"
    FILTERED     = "Filtered"      # body modified / stripped
    RATE_LIMITED = "Rate-Limited"
    ERROR        = "Error"


class MutationKind(str, Enum):
    ORIGINAL        = "original"
    URL_ENCODE      = "url_encode"
    DOUBLE_ENCODE   = "double_encode"
    UNICODE_ESCAPE  = "unicode_escape"
    HTML_ENTITY     = "html_entity"
    MIXED_CASE      = "mixed_case"
    INLINE_COMMENT  = "inline_comment"   # SQL: SE/**/LECT
    WHITESPACE_VAR  = "whitespace_var"
    CHAR_SUBSTITUTE = "char_substitute"
    NULL_BYTE       = "null_byte"


class PayloadKind(str, Enum):
    XSS  = "xss"
    SQLI = "sqli"


# ── WAF Signal ──────────────────────────────────────────────────────────────

@dataclass
class WAFSignal:
    """A single matched detection signal and its contribution weight."""
    description: str
    weight: float          # how much confidence this signal adds (0.0–1.0)
    source: str            # "header" | "body" | "status" | "cookie"


# ── Fingerprint Result ───────────────────────────────────────────────────────

@dataclass
class FingerprintResult:
    vendor: WAFVendor
    confidence: float                           # 0.0–1.0
    signals: list[WAFSignal] = field(default_factory=list)
    raw_headers: dict[str, str] = field(default_factory=dict)
    status_code: int = 0
    ts: float = field(default_factory=time.time)

    @property
    def confidence_pct(self) -> str:
        return f"{self.confidence * 100:.1f}%"

    def to_dict(self) -> dict:
        return {
            "vendor":          self.vendor.value,
            "confidence":      round(self.confidence, 3),
            "confidence_pct":  self.confidence_pct,
            "signals":         [{"desc": s.description, "source": s.source,
                                  "weight": s.weight} for s in self.signals],
            "status_code":     self.status_code,
        }


# ── Mutated Payload ──────────────────────────────────────────────────────────

@dataclass
class MutatedPayload:
    value: str
    kind: MutationKind
    original: str
    category: PayloadKind
    description: str = ""

    def __hash__(self) -> int:
        return hash(self.value)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, MutatedPayload) and self.value == other.value


# ── Probe Result ─────────────────────────────────────────────────────────────

@dataclass
class ProbeResult:
    payload: MutatedPayload
    classification: ResponseClass
    status_code: int
    resp_length: int
    resp_time: float           # seconds
    blocked: bool
    resp_headers: dict[str, str] = field(default_factory=dict)
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "payload":          self.payload.value,
            "original":         self.payload.original,
            "mutation":         self.payload.kind.value,
            "category":         self.payload.category.value,
            "classification":   self.classification.value,
            "status_code":      self.status_code,
            "resp_length":      self.resp_length,
            "resp_time_ms":     round(self.resp_time * 1000, 2),
            "blocked":          self.blocked,
            "notes":            self.notes,
        }


# ── Scan Statistics ───────────────────────────────────────────────────────────

@dataclass
class ScanStats:
    total:        int   = 0
    blocked:      int   = 0
    allowed:      int   = 0
    challenged:   int   = 0
    filtered:     int   = 0
    rate_limited: int   = 0
    errors:       int   = 0
    avg_ms:       float = 0.0

    @property
    def block_rate(self) -> float:
        return (self.blocked / self.total) if self.total else 0.0

    def to_dict(self) -> dict:
        return {
            "total":          self.total,
            "blocked":        self.blocked,
            "allowed":        self.allowed,
            "challenged":     self.challenged,
            "filtered":       self.filtered,
            "rate_limited":   self.rate_limited,
            "errors":         self.errors,
            "block_rate_pct": f"{self.block_rate * 100:.1f}%",
            "avg_ms":         round(self.avg_ms, 2),
        }


# ── Top-Level Scan Result ─────────────────────────────────────────────────────

@dataclass
class ScanResult:
    target:      str
    mode:        str
    fingerprint: Optional[FingerprintResult]
    probes:      list[ProbeResult] = field(default_factory=list)
    stats:       ScanStats         = field(default_factory=ScanStats)
    started_at:  float             = field(default_factory=time.time)
    ended_at:    float             = 0.0
    errors:      list[str]         = field(default_factory=list)

    @property
    def duration(self) -> float:
        return max(0.0, self.ended_at - self.started_at)

    def to_dict(self) -> dict:
        return {
            "target":       self.target,
            "mode":         self.mode,
            "duration_sec": round(self.duration, 2),
            "fingerprint":  self.fingerprint.to_dict() if self.fingerprint else None,
            "stats":        self.stats.to_dict(),
            "probes":       [p.to_dict() for p in self.probes],
            "errors":       self.errors,
        }
