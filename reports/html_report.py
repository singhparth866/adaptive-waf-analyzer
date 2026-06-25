"""
reports/html_report.py — Self-contained dark-theme HTML scan report.

Sections
--------
* WAF Detection panel with confidence bar and matched signals
* Stats grid (blocked / allowed / challenged / filtered / rate-limited / errors)
* Mutation breakdown table — per-technique totals and block rates
* Category breakdown (XSS vs SQLi)
* Full probe results table with sortable columns (vanilla JS)
* Errors section
"""
from __future__ import annotations

import time
from pathlib import Path

from core.models import ResponseClass, ScanResult

# ── HTML skeleton ─────────────────────────────────────────────────────────────
_HEAD = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WAF Scan — {host}</title>
<style>
:root{{
  --bg:#0d1117;--surface:#161b22;--card:#21262d;--border:#30363d;
  --accent:#7c6af7;--accent2:#58a6ff;
  --green:#3fb950;--red:#f85149;--yellow:#d29922;--blue:#58a6ff;--purple:#a371f7;
  --text:#e6edf3;--muted:#8b949e;--dim:#484f58;
}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,-apple-system,sans-serif;
     font-size:13px;line-height:1.6}}
a{{color:var(--accent2);text-decoration:none}}
/* layout */
.wrapper{{max-width:1400px;margin:0 auto;padding:2rem 1.5rem}}
/* header */
.header{{border-bottom:1px solid var(--border);padding-bottom:1.25rem;margin-bottom:2rem}}
.header h1{{font-size:1.5rem;font-weight:700;color:var(--accent);letter-spacing:-.02em}}
.header .meta{{color:var(--muted);font-size:.82rem;margin-top:.3rem}}
.header .meta strong{{color:var(--text)}}
/* section titles */
h2{{font-size:.9rem;font-weight:600;text-transform:uppercase;letter-spacing:.08em;
   color:var(--muted);margin:2rem 0 .75rem;padding-bottom:.4rem;
   border-bottom:1px solid var(--border)}}
/* detection card */
.detect-card{{background:var(--card);border:1px solid var(--border);border-radius:8px;
             padding:1.5rem;margin-bottom:1.5rem;display:flex;gap:2rem;align-items:flex-start;flex-wrap:wrap}}
.detect-name{{font-size:2rem;font-weight:800;color:var(--accent);line-height:1}}
.detect-meta{{color:var(--muted);font-size:.85rem;margin:.4rem 0 .75rem}}
.conf-wrap{{display:flex;align-items:center;gap:.75rem;margin-bottom:1rem}}
.conf-bar{{width:180px;height:8px;background:var(--border);border-radius:4px;overflow:hidden}}
.conf-fill{{height:100%;background:var(--accent);border-radius:4px;transition:width .4s}}
.conf-pct{{font-weight:700;color:var(--accent);font-size:.9rem}}
.signals{{display:flex;flex-wrap:wrap;gap:.4rem;margin-top:.5rem}}
.sig{{background:var(--surface);border:1px solid var(--border);border-radius:4px;
     padding:.2rem .55rem;font-size:.75rem;color:var(--muted)}}
.sig .src{{color:var(--accent2);font-weight:600}}
/* stat grid */
.stat-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:.75rem;margin-bottom:1.5rem}}
.stat{{background:var(--card);border:1px solid var(--border);border-radius:8px;
      padding:1rem;text-align:center}}
.stat-val{{font-size:1.8rem;font-weight:800;line-height:1;margin-bottom:.2rem}}
.stat-lbl{{color:var(--muted);font-size:.75rem;text-transform:uppercase;letter-spacing:.05em}}
.col-red{{color:var(--red)}} .col-green{{color:var(--green)}}
.col-yellow{{color:var(--yellow)}} .col-blue{{color:var(--blue)}}
.col-purple{{color:var(--purple)}} .col-accent{{color:var(--accent)}}
/* breakdown tables */
.breakdown{{display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:1.5rem}}
@media(max-width:700px){{.breakdown{{grid-template-columns:1fr}}}}
/* generic table */
.tbl-wrap{{overflow-x:auto}}
table{{width:100%;border-collapse:collapse;font-size:.8rem}}
thead th{{background:var(--surface);padding:.6rem .75rem;text-align:left;color:var(--muted);
         font-weight:600;border-bottom:2px solid var(--border);white-space:nowrap;cursor:pointer;
         user-select:none}}
thead th:hover{{color:var(--text)}}
thead th::after{{content:' ⇅';opacity:.4;font-size:.7rem}}
thead th.asc::after{{content:' ↑';opacity:1;color:var(--accent)}}
thead th.desc::after{{content:' ↓';opacity:1;color:var(--accent)}}
tbody td{{padding:.5rem .75rem;border-bottom:1px solid var(--border);word-break:break-all;
         vertical-align:top}}
tbody tr:hover td{{background:var(--surface)}}
/* badges */
.badge{{display:inline-block;padding:.15rem .5rem;border-radius:4px;
       font-size:.72rem;font-weight:700;white-space:nowrap}}
.b-blocked{{background:#3d1a1a;color:var(--red)}}
.b-allowed{{background:#1a3d1a;color:var(--green)}}
.b-challenged{{background:#3d2e0a;color:var(--yellow)}}
.b-filtered{{background:#0d2240;color:var(--blue)}}
.b-rate-limited{{background:#1a1a3d;color:var(--purple)}}
.b-error{{background:#1a1a1a;color:var(--dim)}}
/* progress bar in table */
.mini-bar{{width:80px;height:6px;background:var(--border);border-radius:3px;display:inline-block;vertical-align:middle}}
.mini-fill{{height:100%;border-radius:3px}}
/* filter bar */
.filter-bar{{display:flex;gap:.75rem;flex-wrap:wrap;margin-bottom:1rem;align-items:center}}
.filter-bar input, .filter-bar select{{
  background:var(--card);border:1px solid var(--border);color:var(--text);
  border-radius:6px;padding:.35rem .7rem;font-size:.8rem;outline:none}}
.filter-bar input:focus,.filter-bar select:focus{{border-color:var(--accent)}}
.filter-bar label{{color:var(--muted);font-size:.8rem}}
/* count badge */
.count-badge{{background:var(--card);border:1px solid var(--border);border-radius:12px;
            padding:.15rem .6rem;font-size:.75rem;color:var(--muted);margin-left:.5rem}}
/* errors */
.error-list{{background:var(--card);border:1px solid var(--border);border-radius:8px;
           padding:1rem;font-size:.8rem;color:var(--muted)}}
.error-list li{{padding:.2rem 0;border-bottom:1px solid var(--border)}}
.error-list li:last-child{{border:none}}
/* footer */
footer{{color:var(--dim);font-size:.75rem;text-align:center;margin-top:3rem;
       padding-top:1rem;border-top:1px solid var(--border)}}
</style>
</head>
<body><div class="wrapper">"""

_FOOT = """<footer>
  WAF Fingerprinter &amp; Bypass Analyzer &nbsp;·&nbsp;
  For authorized security research only &nbsp;·&nbsp;
  {ts}
</footer>
</div>
<script>
// ── Table sort ────────────────────────────────────────────────────────────────
document.querySelectorAll('table.sortable').forEach(tbl => {{
  const ths = tbl.querySelectorAll('thead th');
  ths.forEach((th, ci) => {{
    th.addEventListener('click', () => {{
      const asc = !th.classList.contains('asc');
      ths.forEach(h => h.classList.remove('asc','desc'));
      th.classList.add(asc ? 'asc' : 'desc');
      const rows = Array.from(tbl.tBodies[0].rows);
      rows.sort((a, b) => {{
        const av = a.cells[ci]?.dataset.val ?? a.cells[ci]?.innerText ?? '';
        const bv = b.cells[ci]?.dataset.val ?? b.cells[ci]?.innerText ?? '';
        const an = parseFloat(av), bn = parseFloat(bv);
        const cmp = isNaN(an)||isNaN(bn) ? av.localeCompare(bv) : an - bn;
        return asc ? cmp : -cmp;
      }});
      rows.forEach(r => tbl.tBodies[0].appendChild(r));
    }});
  }});
}});

// ── Probe table filter ─────────────────────────────────────────────────────
(function() {{
  const input  = document.getElementById('probe-search');
  const catSel = document.getElementById('probe-cat');
  const clsSel = document.getElementById('probe-cls');
  const tbody  = document.getElementById('probe-tbody');
  const cntEl  = document.getElementById('probe-count');
  if (!input || !tbody) return;

  function filter() {{
    const q   = input.value.toLowerCase();
    const cat = catSel.value;
    const cls = clsSel.value;
    let vis = 0;
    tbody.querySelectorAll('tr').forEach(tr => {{
      const text = tr.innerText.toLowerCase();
      const ok = (!q || text.includes(q))
               && (!cat || tr.dataset.cat === cat)
               && (!cls || tr.dataset.cls === cls);
      tr.style.display = ok ? '' : 'none';
      if (ok) vis++;
    }});
    if (cntEl) cntEl.textContent = vis;
  }}
  input.addEventListener('input', filter);
  catSel.addEventListener('change', filter);
  clsSel.addEventListener('change', filter);
}})();
</script>
</body></html>"""


# ── Helpers ───────────────────────────────────────────────────────────────────

def _e(s: str) -> str:
    """HTML-escape a string."""
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;"))


def _badge(cls: str) -> str:
    key = cls.lower().replace(" ", "-").replace("_", "-")
    return f'<span class="badge b-{key}">{_e(cls)}</span>'


def _mini_bar(pct: float, colour: str = "#7c6af7") -> str:
    w = max(0, min(100, pct))
    return (f'<span class="mini-bar"><span class="mini-fill" '
            f'style="width:{w:.0f}%;background:{colour}"></span></span>')


# ── Section builders ──────────────────────────────────────────────────────────

def _header(result: ScanResult, host: str) -> str:
    ts  = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(result.started_at))
    return (
        f'<div class="header">'
        f'<h1>🛡 WAF Scan Report</h1>'
        f'<p class="meta">'
        f'<strong>Target:</strong> {_e(result.target)} &nbsp;·&nbsp; '
        f'<strong>Mode:</strong> {_e(result.mode)} &nbsp;·&nbsp; '
        f'<strong>Started:</strong> {ts} &nbsp;·&nbsp; '
        f'<strong>Duration:</strong> {result.duration:.1f}s'
        f'</p></div>'
    )


def _detection(result: ScanResult) -> str:
    fp   = result.fingerprint
    if not fp:
        return '<p style="color:var(--muted)">No fingerprint data.</p>'
    conf = fp.confidence
    pct  = fp.confidence_pct
    sigs = "".join(
        f'<span class="sig"><span class="src">[{_e(s.source)}]</span> {_e(s.description)} '
        f'<span style="color:var(--accent)">+{s.weight}</span></span>'
        for s in fp.signals
    ) or '<span class="sig">No signals matched</span>'
    return (
        f'<h2>WAF Detection</h2>'
        f'<div class="detect-card">'
        f'  <div>'
        f'    <div class="detect-name">{_e(fp.vendor.value)}</div>'
        f'    <div class="detect-meta">HTTP {fp.status_code}</div>'
        f'    <div class="conf-wrap">'
        f'      <div class="conf-bar"><div class="conf-fill" style="width:{conf*100:.0f}%"></div></div>'
        f'      <span class="conf-pct">{pct}</span>'
        f'    </div>'
        f'    <div class="signals">{sigs}</div>'
        f'  </div>'
        f'</div>'
    )


def _stats_grid(result: ScanResult) -> str:
    s   = result.stats
    d   = s.to_dict()
    cells = [
        ("Total",        str(s.total),                "col-accent"),
        ("Blocked",      str(s.blocked),              "col-red"),
        ("Allowed",      str(s.allowed),              "col-green"),
        ("Challenged",   str(s.challenged),           "col-yellow"),
        ("Filtered",     str(s.filtered),             "col-blue"),
        ("Rate-Limited", str(s.rate_limited),         "col-purple"),
        ("Errors",       str(s.errors),               ""),
        ("Block Rate",   d["block_rate_pct"],         "col-red"),
        ("Avg Resp",     f"{round(s.avg_ms)}ms",      ""),
        ("Duration",     f"{result.duration:.1f}s",   ""),
    ]
    items = "".join(
        f'<div class="stat"><div class="stat-val {col}">{v}</div>'
        f'<div class="stat-lbl">{lbl}</div></div>'
        for lbl, v, col in cells
    )
    return f'<h2>Statistics</h2><div class="stat-grid">{items}</div>'


def _breakdown(result: ScanResult) -> str:
    from collections import defaultdict

    probes = result.probes
    if not probes:
        return ""

    # mutation breakdown
    mut_data: dict = defaultdict(lambda: dict(total=0, blocked=0, allowed=0,
                                               challenged=0, filtered=0))
    for p in probes:
        k = p.payload.kind.value
        mut_data[k]["total"] += 1
        c = p.classification.value.lower()
        if c in mut_data[k]:
            mut_data[k][c] += 1

    mut_rows = ""
    for name, d in sorted(mut_data.items()):
        blk_rate = d["blocked"] / d["total"] * 100 if d["total"] else 0
        mut_rows += (
            f'<tr>'
            f'<td>{_e(name)}</td>'
            f'<td>{d["total"]}</td>'
            f'<td><span class="col-green">{d["allowed"]}</span></td>'
            f'<td><span class="col-red">{d["blocked"]}</span></td>'
            f'<td>{_mini_bar(blk_rate,"#f85149")} {blk_rate:.0f}%</td>'
            f'</tr>'
        )
    mut_tbl = (
        f'<div class="tbl-wrap">'
        f'<table class="sortable"><thead><tr>'
        f'<th data-sort="str">Mutation</th><th data-sort="num">Total</th>'
        f'<th data-sort="num">Allowed</th><th data-sort="num">Blocked</th>'
        f'<th data-sort="num">Block%</th>'
        f'</tr></thead><tbody>{mut_rows}</tbody></table></div>'
    )

    # category breakdown
    cat_data: dict = defaultdict(lambda: dict(total=0, blocked=0, allowed=0))
    for p in probes:
        k = p.payload.category.value
        cat_data[k]["total"] += 1
        if p.blocked:
            cat_data[k]["blocked"] += 1
        elif p.classification == ResponseClass.ALLOWED:
            cat_data[k]["allowed"] += 1

    cat_rows = ""
    for cat, d in sorted(cat_data.items()):
        blk_rate = d["blocked"] / d["total"] * 100 if d["total"] else 0
        cat_rows += (
            f'<tr>'
            f'<td><strong>{_e(cat.upper())}</strong></td>'
            f'<td>{d["total"]}</td>'
            f'<td><span class="col-green">{d["allowed"]}</span></td>'
            f'<td><span class="col-red">{d["blocked"]}</span></td>'
            f'<td>{_mini_bar(blk_rate,"#f85149")} {blk_rate:.0f}%</td>'
            f'</tr>'
        )
    cat_tbl = (
        f'<div class="tbl-wrap">'
        f'<table class="sortable"><thead><tr>'
        f'<th data-sort="str">Category</th><th data-sort="num">Total</th>'
        f'<th data-sort="num">Allowed</th><th data-sort="num">Blocked</th>'
        f'<th data-sort="num">Block%</th>'
        f'</tr></thead><tbody>{cat_rows}</tbody></table></div>'
    )

    return (
        f'<h2>Breakdown</h2>'
        f'<div class="breakdown">'
        f'  <div><h3 style="color:var(--muted);font-size:.8rem;margin-bottom:.5rem">BY MUTATION</h3>{mut_tbl}</div>'
        f'  <div><h3 style="color:var(--muted);font-size:.8rem;margin-bottom:.5rem">BY CATEGORY</h3>{cat_tbl}</div>'
        f'</div>'
    )


def _probe_table(result: ScanResult) -> str:
    if not result.probes:
        return '<p style="color:var(--muted);margin:1rem 0">No payload probes run (passive mode).</p>'

    rows = []
    for p in result.probes:
        cls_key = p.classification.value.lower().replace(" ", "-").replace("_", "-")
        rows.append(
            f'<tr data-cat="{_e(p.payload.category.value)}" data-cls="{_e(p.classification.value)}">'
            f'<td>{_e(p.payload.category.value)}</td>'
            f'<td>{_e(p.payload.kind.value)}</td>'
            f'<td style="font-family:monospace;font-size:.75rem">{_e(p.payload.value[:90])}</td>'
            f'<td>{_badge(p.classification.value)}</td>'
            f'<td data-val="{p.status_code}">{p.status_code}</td>'
            f'<td data-val="{p.resp_length}">{p.resp_length:,}</td>'
            f'<td data-val="{p.resp_time*1000:.0f}">{p.resp_time*1000:.0f}ms</td>'
            f'<td style="color:var(--muted);font-size:.75rem">{_e(p.notes[:80])}</td>'
            f'</tr>'
        )

    total = len(result.probes)
    cats  = sorted({p.payload.category.value for p in result.probes})
    clses = sorted({p.classification.value for p in result.probes})

    cat_opts  = "".join(f'<option value="{c}">{c}</option>' for c in cats)
    cls_opts  = "".join(f'<option value="{c}">{c}</option>' for c in clses)

    return (
        f'<h2>Probe Results <span class="count-badge" id="probe-count">{total}</span></h2>'
        f'<div class="filter-bar">'
        f'  <label>Search</label>'
        f'  <input id="probe-search" placeholder="payload, notes …" style="width:240px">'
        f'  <label>Category</label>'
        f'  <select id="probe-cat"><option value="">All</option>{cat_opts}</select>'
        f'  <label>Classification</label>'
        f'  <select id="probe-cls"><option value="">All</option>{cls_opts}</select>'
        f'</div>'
        f'<div class="tbl-wrap">'
        f'<table class="sortable"><thead><tr>'
        f'<th data-sort="str">Category</th><th data-sort="str">Mutation</th>'
        f'<th data-sort="str">Payload</th>'
        f'<th data-sort="str">Result</th><th data-sort="num">Status</th>'
        f'<th data-sort="num">Length</th><th data-sort="num">Time</th>'
        f'<th data-sort="str">Notes</th>'
        f'</tr></thead>'
        f'<tbody id="probe-tbody">{"".join(rows)}</tbody>'
        f'</table></div>'
    )


def _errors(result: ScanResult) -> str:
    if not result.errors:
        return ""
    items = "".join(f'<li>{_e(e)}</li>' for e in result.errors)
    return (
        f'<h2>Errors ({len(result.errors)})</h2>'
        f'<ul class="error-list">{items}</ul>'
    )


# ── Public writer ─────────────────────────────────────────────────────────────

def write(result: ScanResult, output_dir: str = "./reports") -> Path:
    """Render *result* to a self-contained HTML file and return its path."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    ts   = time.strftime("%Y%m%d_%H%M%S")
    host = _slug(result.target)
    path = Path(output_dir) / f"waf_scan_{host}_{ts}.html"

    body = "".join([
        _HEAD.format(host=_e(host)),
        _header(result, host),
        _detection(result),
        _stats_grid(result),
        _breakdown(result),
        _probe_table(result),
        _errors(result),
        _FOOT.format(ts=time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())),
    ])
    path.write_text(body, encoding="utf-8")
    return path


def _slug(url: str) -> str:
    return (url.replace("https://", "").replace("http://", "")
               .replace("/", "_").replace(":", "_").strip("_")[:50])
