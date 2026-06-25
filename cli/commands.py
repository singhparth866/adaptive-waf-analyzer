"""
cli/commands.py — Full Typer CLI for WAF Fingerprinter & Bypass Analyzer.

Subcommands
-----------
  scan          Full scan: fingerprint + payload probe + report
  fingerprint   Fingerprint only (no payloads, instant result)
  payloads      List/preview payload variants before running a scan
  report        Re-render a JSON report to HTML without re-scanning

Usage
-----
  python main.py scan --url https://target.com --mode aggressive --output both
  python main.py fingerprint --url https://target.com
  python main.py payloads --mode normal --category xss
  python main.py report --input reports/waf_scan_target_20240101_120000.json
"""
from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Optional

import typer
from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.config import Config
from utils.logger import get_logger

# ── App setup ─────────────────────────────────────────────────────────────────
cli = typer.Typer(
    name="waf-analyzer",
    help="WAF Fingerprinter & Adaptive Bypass Analyzer — authorized targets only.",
    add_completion=False,
    no_args_is_help=True,
)
con = Console()
err = Console(stderr=True)


# ── Shared helpers ────────────────────────────────────────────────────────────

def _banner() -> None:
    con.print(Panel.fit(
        "[bold #7c6af7]WAF Fingerprinter & Bypass Analyzer[/bold #7c6af7]\n"
        "[dim]Authorized security research · Bug bounty recon[/dim]",
        border_style="#30363d",
        padding=(0, 2),
    ))


def _normalise_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url


def _build_config(
    mode: str,
    concurrency: int,
    timeout: float,
    rate_limit: float,
    output: str,
    output_dir: str,
    proxy: Optional[str],
    verbose: bool,
    max_payloads: int,
    config_file: Optional[str],
) -> Config:
    base = Config.from_yaml(config_file) if config_file else Config()
    return base.merge({
        "mode": mode, "concurrency": concurrency, "timeout": timeout,
        "rate_limit": rate_limit, "output_format": output,
        "output_dir": output_dir, "proxy": proxy,
        "verbose": verbose, "max_payloads": max_payloads,
    })


def _validate_mode(mode: str) -> None:
    if mode not in ("passive", "normal", "aggressive"):
        err.print(f"[red]Invalid mode '{mode}'. Choose: passive | normal | aggressive[/red]")
        raise typer.Exit(1)


def _print_scan_config(url: str, cfg: Config) -> None:
    tbl = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    tbl.add_column(style="dim", width=16)
    tbl.add_column()
    tbl.add_row("Target",      f"[bold cyan]{url}[/bold cyan]")
    tbl.add_row("Mode",        f"[bold]{cfg.mode}[/bold]")
    tbl.add_row("Concurrency", str(cfg.concurrency))
    tbl.add_row("Timeout",     f"{cfg.timeout}s")
    tbl.add_row("Rate limit",  "off" if cfg.rate_limit == 0 else f"{cfg.rate_limit} req/s")
    tbl.add_row("Output",      cfg.output_format)
    if cfg.proxy:
        tbl.add_row("Proxy", cfg.proxy)
    con.print(tbl)


def _print_fingerprint(result) -> None:
    """Render WAF detection panel."""
    from core.models import WAFVendor
    fp = result.fingerprint
    if not fp or fp.vendor in (WAFVendor.NONE, WAFVendor.UNKNOWN):
        con.print(Panel(
            "[dim]No WAF detected (or insufficient signals)[/dim]",
            title="[bold]WAF Detection[/bold]", border_style="#30363d",
        ))
        return

    conf       = fp.confidence
    bar_fill   = "█" * int(conf * 24)
    bar_empty  = "░" * (24 - len(bar_fill))
    signal_txt = "\n".join(
        f"  [dim][{s.source:7}][/dim] {s.description}  "
        f"[dim #7c6af7](+{s.weight})[/dim]"
        for s in fp.signals
    ) or "  [dim]No signals[/dim]"

    con.print(Panel(
        f"[bold #7c6af7]{fp.vendor.value}[/bold #7c6af7]\n"
        f"[dim]Confidence:[/dim] [bold]{fp.confidence_pct}[/bold]  "
        f"[#7c6af7]{bar_fill}[/][dim]{bar_empty}[/dim]\n"
        f"[dim]Status code:[/dim] {fp.status_code}\n\n"
        f"[dim]Matched signals:[/dim]\n{signal_txt}",
        title="[bold]WAF Detection[/bold]",
        border_style="#7c6af7",
    ))


def _print_stats(result) -> None:
    """Render statistics table."""
    if not result.probes:
        con.print("[dim]Passive mode — no payload probes run.[/dim]\n")
        return

    s = result.stats
    d = s.to_dict()

    tbl = Table(
        title="Scan Statistics",
        box=box.SIMPLE_HEAVY,
        show_header=True,
        header_style="bold #7c6af7",
        title_style="bold",
        padding=(0, 1),
    )
    tbl.add_column("Metric",         style="dim", width=20)
    tbl.add_column("Value",          justify="right")
    tbl.add_column("Visual",         justify="left",  width=28)

    def _bar(n: int, total: int, colour: str) -> str:
        if total == 0:
            return ""
        w = int(n / total * 20)
        return f"[{colour}]{'█' * w}[/{colour}][dim]{'░' * (20 - w)}[/dim]"

    total = s.total or 1
    rows = [
        ("Total probes",   str(s.total),          ""),
        ("Blocked",        f"[red]{s.blocked}[/]",       _bar(s.blocked,   total, "red")),
        ("Allowed",        f"[green]{s.allowed}[/]",     _bar(s.allowed,   total, "green")),
        ("Challenged",     f"[yellow]{s.challenged}[/]", _bar(s.challenged,total, "yellow")),
        ("Filtered",       f"[blue]{s.filtered}[/]",     _bar(s.filtered,  total, "blue")),
        ("Rate-limited",   str(s.rate_limited),   _bar(s.rate_limited, total, "cyan")),
        ("Errors",         str(s.errors),         ""),
        ("Block rate",     f"[bold red]{d['block_rate_pct']}[/]",  ""),
        ("Avg resp time",  f"{round(s.avg_ms)}ms",               ""),
        ("Total duration", f"{result.duration:.1f}s",            ""),
    ]
    for metric, val, bar in rows:
        tbl.add_row(metric, val, bar)
    con.print(tbl)


def _print_mutation_breakdown(result) -> None:
    """Per-mutation-type block/allow breakdown."""
    from collections import defaultdict
    probes = result.probes
    if not probes:
        return

    data: dict = defaultdict(lambda: dict(total=0, blocked=0, allowed=0))
    for p in probes:
        k = p.payload.kind.value
        data[k]["total"] += 1
        if p.blocked:
            data[k]["blocked"] += 1
        elif p.classification.value == "Allowed":
            data[k]["allowed"] += 1

    tbl = Table(
        title="Mutation Breakdown",
        box=box.SIMPLE_HEAVY,
        header_style="bold #7c6af7",
        title_style="bold",
        padding=(0, 1),
    )
    tbl.add_column("Mutation Type",  width=22)
    tbl.add_column("Total",   justify="right", width=7)
    tbl.add_column("Allowed", justify="right", width=8, style="green")
    tbl.add_column("Blocked", justify="right", width=8, style="red")
    tbl.add_column("Block %", justify="right", width=8)
    tbl.add_column("Bar", width=22)

    for name, d in sorted(data.items()):
        br   = d["blocked"] / d["total"] * 100 if d["total"] else 0
        fill = int(br / 5)
        bar  = f"[red]{'█' * fill}[/][dim]{'░' * (20 - fill)}[/dim]"
        tbl.add_row(
            name, str(d["total"]),
            str(d["allowed"]), str(d["blocked"]),
            f"{br:.0f}%", bar,
        )
    con.print(tbl)


def _print_allowed_payloads(result, limit: int = 25) -> None:
    """Print payloads that were NOT blocked — the key recon output."""
    from core.models import ResponseClass
    allowed = [p for p in result.probes if p.classification == ResponseClass.ALLOWED]
    if not allowed:
        con.print("[dim]No payloads passed unblocked.[/dim]\n")
        return

    con.print(
        f"\n[bold green]Payloads not blocked[/bold green] "
        f"[dim]({len(allowed)} of {result.stats.total})[/dim]"
    )
    tbl = Table(box=box.MINIMAL, header_style="dim", padding=(0, 1))
    tbl.add_column("Cat",      width=6)
    tbl.add_column("Mutation", width=18)
    tbl.add_column("Payload",  max_width=70)
    tbl.add_column("Status",   justify="right", width=7)
    tbl.add_column("ms",       justify="right", width=6)

    for p in allowed[:limit]:
        tbl.add_row(
            p.payload.category.value,
            p.payload.kind.value,
            p.payload.value[:70],
            str(p.status_code),
            str(round(p.resp_time * 1000)),
        )
    if len(allowed) > limit:
        tbl.add_row(
            "[dim]…[/dim]", "",
            f"[dim]+{len(allowed) - limit} more — see report file[/dim]",
            "", "",
        )
    con.print(tbl)


def _write_reports(result, cfg: Config) -> list[str]:
    from reports import json_report, html_report
    written = []
    if cfg.output_format in ("json", "both"):
        p = json_report.write(result, cfg.output_dir)
        written.append(str(p))
    if cfg.output_format in ("html", "both"):
        p = html_report.write(result, cfg.output_dir)
        written.append(str(p))
    return written


# ── scan subcommand ───────────────────────────────────────────────────────────

@cli.command()
def scan(
    url: str = typer.Option(
        ..., "--url", "-u", help="Target URL (must be authorised)",
    ),
    mode: str = typer.Option(
        "normal", "--mode", "-m",
        help="Scan mode: passive | normal | aggressive",
    ),
    concurrency: int = typer.Option(10,   "--concurrency", "-c", help="Concurrent requests"),
    timeout:   float = typer.Option(10.0, "--timeout",     "-t", help="Per-request timeout (s)"),
    rate_limit: float = typer.Option(0.0, "--rate-limit",  "-r", help="Req/s cap (0 = off)"),
    output:     str  = typer.Option("json", "--output",    "-o", help="json | html | both"),
    output_dir: str  = typer.Option("./reports", "--output-dir", help="Report output directory"),
    proxy: Optional[str]  = typer.Option(None,  "--proxy",   help="Proxy URL"),
    config_file: Optional[str] = typer.Option(None, "--config", help="Path to config.yaml"),
    verbose:    bool = typer.Option(False, "--verbose", "-v", help="Debug output", is_flag=True),
    xss_only:   bool = typer.Option(False, "--xss-only",  help="XSS payloads only", is_flag=True),
    sqli_only:  bool = typer.Option(False, "--sqli-only", help="SQLi payloads only", is_flag=True),
    max_payloads: int = typer.Option(0, "--max-payloads", help="Cap payload count (0 = all)"),
    no_banner:  bool = typer.Option(False, "--no-banner", help="Suppress banner", is_flag=True),
) -> None:
    """Run a full WAF fingerprint + payload probe scan."""
    if not no_banner:
        _banner()
    _validate_mode(mode)
    get_logger("cli", verbose)

    url = _normalise_url(url)
    cfg = _build_config(mode, concurrency, timeout, rate_limit,
                        output, output_dir, proxy, verbose,
                        max_payloads, config_file)
    _print_scan_config(url, cfg)

    # Build payload list
    payloads = []
    if cfg.test_payloads:
        from payloads.loader import load_all, load_mutated, PayloadKind
        n = cfg.mutations_per_payload
        if xss_only:
            payloads = load_mutated(PayloadKind.XSS, n)
        elif sqli_only:
            payloads = load_mutated(PayloadKind.SQLI, n)
        else:
            payloads = load_all(n)
        con.print(f"[dim]Loaded [bold]{len(payloads)}[/bold] payload variants[/dim]\n")

    from engine.scanner import Scanner
    scanner = Scanner(cfg)
    try:
        result = asyncio.run(scanner.run(url, payloads))
    except KeyboardInterrupt:
        err.print("\n[yellow]Scan interrupted by user.[/yellow]")
        raise typer.Exit(130)
    except Exception as exc:
        err.print(f"\n[red]Scan failed:[/red] {exc}")
        if verbose:
            import traceback; traceback.print_exc()
        raise typer.Exit(1)

    # Output
    con.print()
    _print_fingerprint(result)
    _print_stats(result)
    if result.probes:
        _print_mutation_breakdown(result)
        _print_allowed_payloads(result)

    written = _write_reports(result, cfg)
    if written:
        con.print("\n[bold]Reports saved:[/bold]")
        for w in written:
            con.print(f"  [dim]→[/dim] {w}")
    con.print()


# ── fingerprint subcommand ────────────────────────────────────────────────────

@cli.command()
def fingerprint(
    url: str = typer.Option(
        ..., "--url", "-u", help="Target URL",
    ),
    probes: int = typer.Option(3, "--probes", "-p", help="Number of baseline requests"),
    timeout: float = typer.Option(10.0, "--timeout", "-t", help="Per-request timeout (s)"),
    proxy: Optional[str] = typer.Option(None, "--proxy", help="Proxy URL"),
    verbose: bool = typer.Option(False, "--verbose", "-v", is_flag=True),
    output:  str  = typer.Option("none", "--output", "-o", help="none | json"),
    output_dir: str = typer.Option("./reports", "--output-dir"),
    no_banner: bool = typer.Option(False, "--no-banner", is_flag=True),
) -> None:
    """Quick WAF fingerprint — no payloads, just detection signals."""
    if not no_banner:
        _banner()
    get_logger("cli", verbose)

    url = _normalise_url(url)
    cfg = Config(mode="passive", timeout=timeout, proxy=proxy, verbose=verbose,
                 baseline_count=probes if hasattr(Config, "baseline_count") else 3)

    con.print(f"[dim]Fingerprinting [bold cyan]{url}[/bold cyan] …[/dim]\n")

    from engine.scanner import Scanner
    from payloads.loader import PayloadKind
    scanner = Scanner(cfg)
    try:
        result = asyncio.run(scanner.run(url, []))
    except KeyboardInterrupt:
        raise typer.Exit(130)
    except Exception as exc:
        err.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    _print_fingerprint(result)

    # Also dump all_detections if any layered WAFs found
    fp = result.fingerprint
    if fp:
        con.print(f"[dim]Baseline avg:[/dim] {result.stats.avg_ms:.0f}ms")
        con.print(f"[dim]Scan took:[/dim]   {result.duration:.2f}s\n")

    if output == "json":
        from reports import json_report
        p = json_report.write(result, output_dir)
        con.print(f"[dim]→[/dim] {p}")


# ── payloads subcommand ───────────────────────────────────────────────────────

@cli.command()
def payloads(
    mode: str = typer.Option(
        "normal", "--mode", "-m", help="passive | normal | aggressive",
    ),
    category: str = typer.Option(
        "all", "--category", "-c", help="all | xss | sqli",
    ),
    mutation: str = typer.Option(
        "all", "--mutation", help="Filter by mutation type (e.g. url_encode)",
    ),
    limit: int = typer.Option(
        50, "--limit", "-l", help="Max rows to show (0 = all)",
    ),
    show_original: bool = typer.Option(
        False, "--show-original", help="Show original pre-mutation value", is_flag=True,
    ),
) -> None:
    """Preview the payload variants that would be used in a scan."""
    _validate_mode(mode)

    from payloads.loader import load_all, load_mutated, load_originals, PayloadKind
    from core.config import Config

    cfg = Config(mode=mode)
    n   = cfg.mutations_per_payload

    if category == "xss":
        pool = load_mutated(PayloadKind.XSS, n)
    elif category == "sqli":
        pool = load_mutated(PayloadKind.SQLI, n)
    else:
        pool = load_all(n)

    if mutation != "all":
        pool = [p for p in pool if mutation.lower() in p.kind.value.lower()]

    total = len(pool)
    display = pool[:limit] if limit else pool

    tbl = Table(
        title=f"Payload Preview  [dim]({total} total)[/dim]",
        box=box.SIMPLE_HEAVY,
        header_style="bold #7c6af7",
        title_style="bold",
        padding=(0, 1),
    )
    tbl.add_column("Cat",      width=6)
    tbl.add_column("Mutation", width=20)
    tbl.add_column("Value",    max_width=80)
    if show_original:
        tbl.add_column("Original", max_width=50)

    for p in display:
        row = [p.category.value, p.kind.value, p.value]
        if show_original:
            row.append(p.original if p.original != p.value else "[dim]—[/dim]")
        tbl.add_row(*row)

    if limit and total > limit:
        tbl.add_row("[dim]…[/dim]", "", f"[dim]+{total - limit} more[/dim]")

    con.print(tbl)
    con.print(
        f"\n[dim]Mode=[bold]{mode}[/bold]  "
        f"mutations_per_payload=[bold]{n}[/bold]  "
        f"total=[bold]{total}[/bold][/dim]\n"
    )


# ── report subcommand ─────────────────────────────────────────────────────────

@cli.command()
def report(
    input_file: str = typer.Option(
        ..., "--input", "-i", help="Path to existing JSON report",
    ),
    output_dir: str = typer.Option("./reports", "--output-dir"),
    no_banner:  bool = typer.Option(False, "--no-banner", is_flag=True),
) -> None:
    """Re-render an existing JSON report to HTML without re-scanning."""
    if not no_banner:
        _banner()

    path = Path(input_file)
    if not path.exists():
        err.print(f"[red]File not found:[/red] {input_file}")
        raise typer.Exit(1)
    if path.suffix.lower() != ".json":
        err.print("[red]Input must be a .json report file.[/red]")
        raise typer.Exit(1)

    con.print(f"[dim]Loading [bold]{input_file}[/bold] …[/dim]")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        err.print(f"[red]Invalid JSON:[/red] {exc}")
        raise typer.Exit(1)

    # Re-hydrate a minimal ScanResult for the HTML renderer
    from core.models import (ScanResult, ScanStats, FingerprintResult,
                              WAFVendor, WAFSignal, ProbeResult,
                              MutatedPayload, MutationKind, PayloadKind,
                              ResponseClass)
    import time as _time

    scan_data = raw.get("scan_result", raw)   # handle both schema versions
    fp_d      = scan_data.get("fingerprint") or {}
    stats_d   = scan_data.get("stats") or scan_data.get("statistics") or {}

    fp = None
    if fp_d:
        try:
            fp = FingerprintResult(
                vendor=WAFVendor(fp_d.get("vendor", "Unknown")),
                confidence=fp_d.get("confidence", 0.0),
                status_code=fp_d.get("status_code", 0),
                signals=[
                    WAFSignal(
                        description=s.get("desc", s.get("description", "")),
                        weight=s.get("weight", 0.0),
                        source=s.get("source", ""),
                    )
                    for s in fp_d.get("signals", [])
                ],
            )
        except Exception:
            fp = FingerprintResult(vendor=WAFVendor.UNKNOWN, confidence=0.0)

    probes: list[ProbeResult] = []
    for pd in scan_data.get("probes", []):
        try:
            mp = MutatedPayload(
                value=pd.get("payload", ""),
                kind=MutationKind(pd.get("mutation", "original")),
                original=pd.get("original", pd.get("payload", "")),
                category=PayloadKind(pd.get("category", "xss")),
            )
            probes.append(ProbeResult(
                payload=mp,
                classification=ResponseClass(pd.get("classification", "Allowed")),
                status_code=pd.get("status_code", 0),
                resp_length=pd.get("resp_length", pd.get("response_length", 0)),
                resp_time=pd.get("resp_time_ms", 0) / 1000,
                blocked=pd.get("blocked", False),
                notes=pd.get("notes", ""),
            ))
        except Exception:
            continue

    result = ScanResult(
        target=scan_data.get("target_url", scan_data.get("target", "")),
        mode=scan_data.get("scan_mode", scan_data.get("mode", "normal")),
        fingerprint=fp,
        probes=probes,
        started_at=_time.time(),
        ended_at=_time.time() + scan_data.get("duration_sec", 0),
        errors=scan_data.get("errors", []),
    )

    from reports import html_report
    out = html_report.write(result, output_dir)
    con.print(f"[bold]HTML report written:[/bold]\n  [dim]→[/dim] {out}\n")
