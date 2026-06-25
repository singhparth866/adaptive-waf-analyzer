"""
engine/scanner.py — Production async WAF scanning engine.

Phases
------
1. Baseline  : N benign GET requests → fingerprint WAF + establish response baseline
2. Probe     : Fire each MutatedPayload via Dispatcher, classify each response
3. Aggregate : Compute ScanStats, return populated ScanResult

Features
--------
* Rich live progress bar with ETA during probe phase
* Per-probe callback hook for external consumers (streaming CLI)
* All probe errors caught individually — one bad probe never aborts the scan
* Phase 1 runs identify_all() to catch layered WAF stacks (e.g. Cloudflare + ModSecurity)
* Baseline response time + length tracked and used by response analyzer
* Scan can be cancelled cleanly via KeyboardInterrupt
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Callable, Optional
from urllib.parse import urlencode

import httpx
from rich.progress import (
    BarColumn, MofNCompleteColumn, Progress,
    SpinnerColumn, TaskID, TextColumn, TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.console import Console

from core.config import Config
from core.models import (
    FingerprintResult, MutatedPayload, ProbeResult,
    ResponseClass, ScanResult, ScanStats, WAFVendor,
)
from core.classifiers.orchestrator import FingerprintOrchestrator
from core.analyzers.response_analyzer import ResponseAnalyzer
from engine.dispatcher import Dispatcher
from utils.logger import get_logger

_console = Console(stderr=True)

# Optional callback fired after every completed probe — used by CLI for live output
ProbeCallback = Callable[[ProbeResult], None]


@dataclass
class _Phase1Result:
    """Internal result from the fingerprinting phase."""
    fingerprint:     FingerprintResult
    all_detections:  list[FingerprintResult]   # catches layered WAFs
    baseline_length: int                        # median response length (bytes)
    baseline_ms:     float                      # median response time (ms)


class Scanner:
    """
    Orchestrates a complete WAF scan: fingerprint → probe → aggregate.

    Usage::

        cfg     = Config(mode="normal", concurrency=10)
        scanner = Scanner(cfg)
        result  = asyncio.run(scanner.run("https://target.com", payloads))
        print(result.fingerprint.vendor, result.stats.to_dict())
    """

    def __init__(
        self,
        config: Config,
        on_probe: Optional[ProbeCallback] = None,
    ) -> None:
        self._cfg      = config
        self._orch     = FingerprintOrchestrator()
        self._log      = get_logger(__name__, config.verbose)
        self._on_probe = on_probe   # optional live callback

    # ── Public entry point ────────────────────────────────────────────────────

    async def run(
        self,
        target: str,
        payloads: list[MutatedPayload],
    ) -> ScanResult:
        """
        Run a full scan against *target*.
        Returns a :class:`ScanResult` regardless of how many probes fail.
        """
        result = ScanResult(
            target=target,
            mode=self._cfg.mode,
            fingerprint=None,
            started_at=time.time(),
        )

        async with Dispatcher(self._cfg) as disp:

            # ── Phase 1: Fingerprint ──────────────────────────────────────────
            self._log.info(
                f"[bold]Phase 1[/bold] — Fingerprinting [cyan]{target}[/cyan] …"
            )
            p1 = await self._phase_fingerprint(disp, target, result)
            result.fingerprint = p1.fingerprint
            self._log_fingerprint(p1)

            # ── Phase 2: Payload probing ──────────────────────────────────────
            if self._cfg.test_payloads and payloads:
                capped = (
                    payloads[: self._cfg.max_payloads]
                    if self._cfg.max_payloads
                    else payloads
                )
                self._log.info(
                    f"[bold]Phase 2[/bold] — Probing "
                    f"[bold]{len(capped)}[/bold] payloads "
                    f"[dim](concurrency={self._cfg.concurrency}, "
                    f"timeout={self._cfg.timeout}s)[/dim] …"
                )
                analyzer = ResponseAnalyzer(
                    baseline_length=p1.baseline_length,
                    length_threshold=0.20,
                )
                result.probes = await self._phase_probe(
                    disp, target, capped, analyzer
                )
            else:
                self._log.info(
                    "[dim]Phase 2 skipped — passive mode or no payloads[/dim]"
                )

        result.ended_at = time.time()
        result.stats    = _compute_stats(result.probes)
        self._log_summary(result)
        return result

    # ── Phase 1 ───────────────────────────────────────────────────────────────

    async def _phase_fingerprint(
        self,
        disp: Dispatcher,
        target: str,
        result: ScanResult,
    ) -> _Phase1Result:
        fp_url      = _join(target, self._cfg.fingerprint_path)
        best:       Optional[FingerprintResult] = None
        all_fps:    list[FingerprintResult]     = []
        lengths:    list[int]                   = []
        times:      list[float]                 = []

        for i in range(self._cfg.baseline_count):
            self._log.debug(
                f"  Baseline probe {i + 1}/{self._cfg.baseline_count} → {fp_url}"
            )
            try:
                resp, elapsed = await disp.get(fp_url)
                lengths.append(len(resp.content))
                times.append(elapsed)

                # identify_all() detects layered WAF stacks
                detected = self._orch.identify_all(resp)
                if detected:
                    all_fps = detected
                    if best is None or detected[0].confidence > best.confidence:
                        best = detected[0]
                elif best is None:
                    best = self._orch.identify(resp)

            except httpx.TimeoutException as exc:
                msg = f"Baseline probe {i + 1} timed out: {exc}"
                result.errors.append(msg)
                self._log.warning(msg)
            except httpx.ConnectError as exc:
                msg = f"Baseline probe {i + 1} connection error: {exc}"
                result.errors.append(msg)
                self._log.warning(msg)
            except Exception as exc:
                msg = f"Baseline probe {i + 1} unexpected error: {exc}"
                result.errors.append(msg)
                self._log.warning(msg)

        fallback = FingerprintResult(
            vendor=WAFVendor.UNKNOWN, confidence=0.0, status_code=0
        )
        baseline_length = (
            int(sum(lengths) / len(lengths)) if lengths else 0
        )
        baseline_ms = (
            sum(times) / len(times) * 1000 if times else 0.0
        )
        return _Phase1Result(
            fingerprint=best or fallback,
            all_detections=all_fps,
            baseline_length=baseline_length,
            baseline_ms=baseline_ms,
        )

    # ── Phase 2 ───────────────────────────────────────────────────────────────

    async def _phase_probe(
        self,
        disp: Dispatcher,
        target: str,
        payloads: list[MutatedPayload],
        analyzer: ResponseAnalyzer,
    ) -> list[ProbeResult]:
        tasks         = [self._probe_one(disp, target, p, analyzer) for p in payloads]
        results:        list[ProbeResult] = []

        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=35),
            MofNCompleteColumn(),
            TextColumn("•"),
            TimeElapsedColumn(),
            TextColumn("eta"),
            TimeRemainingColumn(),
            console=_console,
            transient=True,
        )
        task_id: TaskID = progress.add_task(
            "[cyan]Probing…", total=len(payloads)
        )

        with progress:
            for coro in asyncio.as_completed(tasks):
                try:
                    probe = await coro
                except Exception as exc:
                    self._log.warning(f"Probe task error: {exc}")
                    continue

                results.append(probe)
                progress.advance(task_id)

                # Fire optional callback (used by CLI for live per-probe output)
                if self._on_probe:
                    try:
                        self._on_probe(probe)
                    except Exception:
                        pass

                colour = "red" if probe.blocked else "green"
                self._log.debug(
                    f"  [{probe.payload.category.value:5}] "
                    f"[dim]{probe.payload.kind.value:20}[/dim] "
                    f"[{colour}]{probe.classification.value:12}[/{colour}] "
                    f"HTTP {probe.status_code}  "
                    f"{probe.payload.value[:55]}"
                )

        return results

    # ── Single probe ──────────────────────────────────────────────────────────

    async def _probe_one(
        self,
        disp: Dispatcher,
        target: str,
        payload: MutatedPayload,
        analyzer: ResponseAnalyzer,
    ) -> ProbeResult:
        url = _inject(target, self._cfg.inject_param, payload.value)

        try:
            resp, elapsed = await disp.get(url)
        except httpx.TimeoutException:
            return ProbeResult(
                payload=payload,
                classification=ResponseClass.ERROR,
                status_code=0,
                resp_length=0,
                resp_time=self._cfg.timeout,
                blocked=False,
                notes="Request timed out",
            )
        except httpx.ConnectError as exc:
            return ProbeResult(
                payload=payload,
                classification=ResponseClass.ERROR,
                status_code=0,
                resp_length=0,
                resp_time=0.0,
                blocked=False,
                notes=f"Connection error: {exc}",
            )
        except Exception as exc:
            return ProbeResult(
                payload=payload,
                classification=ResponseClass.ERROR,
                status_code=0,
                resp_length=0,
                resp_time=0.0,
                blocked=False,
                notes=f"Unexpected error: {exc}",
            )

        an = analyzer.analyse(resp, elapsed)
        return ProbeResult(
            payload=payload,
            classification=an.classification,
            status_code=an.status_code,
            resp_length=an.resp_length,
            resp_time=an.resp_time,
            blocked=an.blocked,
            resp_headers=an.resp_headers,
            notes="; ".join(an.signals) if an.signals else "",
        )

    # ── Logging helpers ───────────────────────────────────────────────────────

    def _log_fingerprint(self, p1: _Phase1Result) -> None:
        fp = p1.fingerprint
        bar_filled  = "█" * int(fp.confidence * 20)
        bar_empty   = "░" * (20 - len(bar_filled))
        self._log.info(
            f"  WAF   → [bold #7c6af7]{fp.vendor.value}[/]  "
            f"confidence [bold]{fp.confidence_pct}[/]  "
            f"[#7c6af7]{bar_filled}[/][dim]{bar_empty}[/dim]  "
            f"[dim]baseline {p1.baseline_ms:.0f}ms / "
            f"{p1.baseline_length} bytes[/dim]"
        )
        for sig in fp.signals:
            self._log.debug(
                f"    [[dim]{sig.source:7}[/]] {sig.description}  "
                f"[dim](weight +{sig.weight})[/dim]"
            )
        # Report layered WAFs (e.g. Cloudflare in front of ModSecurity)
        if len(p1.all_detections) > 1:
            others = ", ".join(
                f"{r.vendor.value} ({r.confidence_pct})"
                for r in p1.all_detections[1:]
            )
            self._log.info(f"  [dim]Also detected: {others}[/dim]")

    def _log_summary(self, result: ScanResult) -> None:
        s = result.stats
        self._log.info(
            f"[bold]Scan complete[/bold] — {result.duration:.1f}s  "
            f"[red]{s.blocked} blocked[/red]  "
            f"[green]{s.allowed} allowed[/green]  "
            f"[yellow]{s.challenged} challenged[/yellow]  "
            f"[blue]{s.filtered} filtered[/blue]  "
            f"block_rate=[bold]{s.to_dict()['block_rate_pct']}[/bold]"
        )


# ── Module-level helpers ──────────────────────────────────────────────────────

def _join(target: str, path: str) -> str:
    """Join base URL and a path segment safely."""
    return target.rstrip("/") + "/" + path.lstrip("/")


def _inject(target: str, param: str, value: str) -> str:
    """Append payload as a query-string parameter."""
    base = target.rstrip("/")
    sep  = "&" if "?" in base else "?"
    return f"{base}{sep}{urlencode({param: value})}"


def _compute_stats(probes: list[ProbeResult]) -> ScanStats:
    """Aggregate probe results into a ScanStats summary."""
    s     = ScanStats(total=len(probes))
    times: list[float] = []
    for p in probes:
        times.append(p.resp_time)
        match p.classification:
            case ResponseClass.BLOCKED:      s.blocked      += 1
            case ResponseClass.ALLOWED:      s.allowed      += 1
            case ResponseClass.CHALLENGED:   s.challenged   += 1
            case ResponseClass.FILTERED:     s.filtered     += 1
            case ResponseClass.RATE_LIMITED: s.rate_limited += 1
            case ResponseClass.ERROR:        s.errors       += 1
    s.avg_ms = (sum(times) / len(times) * 1000) if times else 0.0
    return s
