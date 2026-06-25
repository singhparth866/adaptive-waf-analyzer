"""Configuration management — YAML file + CLI override support."""
from __future__ import annotations

from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Optional

import yaml


@dataclass
class Config:
    # ── HTTP ────────────────────────────────────────────────────────────────
    timeout: float = 10.0
    max_retries: int = 3
    concurrency: int = 10
    rate_limit: float = 0.0          # req/s  (0 = unlimited)
    verify_ssl: bool = True

    # ── Proxy ────────────────────────────────────────────────────────────────
    proxy: Optional[str] = None

    # ── Scan behaviour ────────────────────────────────────────────────────────
    mode: str = "normal"             # passive | normal | aggressive
    inject_param: str = "q"          # query-string key for payload injection
    fingerprint_path: str = "/"      # path used for fingerprint probes

    # ── Output ───────────────────────────────────────────────────────────────
    output_format: str = "json"      # json | html | both
    output_dir: str = "./reports"
    verbose: bool = False

    # ── Extra request headers ─────────────────────────────────────────────────
    extra_headers: dict[str, str] = field(default_factory=dict)

    # ── Limits ───────────────────────────────────────────────────────────────
    max_payloads: int = 0            # 0 = unlimited

    # ── Computed properties ────────────────────────────────────────────────

    @property
    def mutations_per_payload(self) -> int:
        return {"passive": 0, "normal": 4, "aggressive": 9}.get(self.mode, 4)

    @property
    def test_payloads(self) -> bool:
        return self.mode != "passive"

    @property
    def baseline_count(self) -> int:
        return {"passive": 1, "normal": 2, "aggressive": 3}.get(self.mode, 2)

    # ── Constructors ──────────────────────────────────────────────────────────

    @classmethod
    def from_yaml(cls, path: str) -> "Config":
        p = Path(path)
        if not p.exists():
            return cls()
        with open(p) as f:
            raw = yaml.safe_load(f) or {}
        data = raw.get("scan", {})
        valid = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in valid})

    @classmethod
    def from_dict(cls, data: dict) -> "Config":
        valid = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in valid})

    def merge(self, overrides: dict) -> "Config":
        """Return a new Config with *overrides* applied (for CLI flags)."""
        current = {f.name: getattr(self, f.name) for f in fields(self)}
        current.update({k: v for k, v in overrides.items() if v is not None})
        return Config.from_dict(current)
