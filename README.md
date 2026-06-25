# WAF Fingerprinter & Adaptive Bypass Analyzer

A professional, async WAF reconnaissance and detection coverage tool for
authorized bug bounty engagements and security research.

> **Legal notice:** Only use against systems you own or have explicit written
> permission to test. Unauthorized scanning is illegal in most jurisdictions.

---

## Features

| Component | Description |
|---|---|
| **6 WAF Detectors** | Cloudflare, Akamai, ModSecurity, AWS WAF, Imperva, F5 BIG-IP |
| **Multi-signal fingerprinting** | Headers, cookies, body patterns, status codes — with confidence scoring |
| **Mutation engine** | URL/double encoding, unicode, HTML entities, mixed case, SQL comments, char substitution |
| **Async scanner** | `httpx` + `asyncio`, concurrent probing, retry logic, rate limiting, proxy support |
| **Response classifier** | Allowed / Blocked / Challenged / Filtered / Rate-Limited |
| **JSON + HTML reports** | Structured output with payload result matrix |
| **Rich CLI** | Full Typer interface with verbose mode, xss/sqli filters, output control |

---

## Installation

```bash
git clone https://github.com/yourhandle/waf-analyzer
cd waf-analyzer
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

**Python 3.11+ required.**

---

## Usage

### Passive fingerprint only (no payload probing)
```bash
python main.py --url https://target.com --mode passive
```

### Normal scan — fingerprint + OWASP test vectors
```bash
python main.py --url https://target.com --mode normal
```

### Aggressive scan — full payload set + all 9 mutation techniques
```bash
python main.py --url https://target.com --mode aggressive --output both -v
```

### Scope-limited probing
```bash
# XSS payloads only
python main.py --url https://target.com --mode normal --xss-only

# SQLi payloads only
python main.py --url https://target.com --mode normal --sqli-only

# Cap total probes (useful during rate-limited engagements)
python main.py --url https://target.com --mode aggressive --max-payloads 50
```

### Route through Burp Suite proxy
```bash
python main.py --url https://target.com --proxy http://127.0.0.1:8080 --mode normal
```

### Tune concurrency and rate limiting
```bash
# Slow, polite scan — 2 concurrent, 1 req/s
python main.py --url https://target.com -c 2 -r 1.0 --mode normal

# Fast scan — 20 concurrent
python main.py --url https://target.com -c 20 --mode aggressive
```

---

## CLI Reference

| Flag | Default | Description |
|---|---|---|
| `--url` / `-u` | required | Target URL |
| `--mode` / `-m` | `normal` | `passive` \| `normal` \| `aggressive` |
| `--concurrency` / `-c` | `10` | Simultaneous async requests |
| `--timeout` / `-t` | `10.0` | Per-request timeout (seconds) |
| `--rate-limit` / `-r` | `0` | Requests/second (0 = unlimited) |
| `--output` / `-o` | `json` | `json` \| `html` \| `both` |
| `--output-dir` | `./reports` | Report output directory |
| `--proxy` | None | Proxy URL |
| `--config` | None | Path to `config.yaml` |
| `--xss-only` | False | Only test XSS payloads |
| `--sqli-only` | False | Only test SQLi payloads |
| `--max-payloads` | 0 | Cap total payload count (0 = all) |
| `--verbose` / `-v` | False | Debug logging |

---

## Scan Modes

| Mode | Fingerprint probes | Payloads | Mutations/payload |
|---|---|---|---|
| `passive` | 1 | None | — |
| `normal` | 2 | XSS + SQLi | 4 |
| `aggressive` | 3 | XSS + SQLi | 9 |

---

## Project Structure

```
waf-analyzer/
├── core/
│   ├── models.py              # Shared dataclasses and enums
│   ├── config.py              # Config dataclass (YAML + CLI merge)
│   ├── fingerprints/          # Per-vendor WAF detectors
│   │   ├── base.py
│   │   ├── cloudflare.py
│   │   ├── akamai.py
│   │   ├── modsecurity.py
│   │   ├── aws_waf.py
│   │   ├── imperva.py
│   │   └── f5_bigip.py
│   ├── mutations/             # Encoding + obfuscation library
│   │   ├── encoder.py         # URL, double, unicode, HTML entity, hex, null-byte
│   │   └── obfuscator.py      # Case, SQL comments, whitespace, char sub
│   ├── analyzers/
│   │   └── response_analyzer.py  # Classifies responses
│   └── classifiers/
│       └── orchestrator.py    # Runs all detectors, returns best match
├── engine/
│   └── scanner.py             # Async scanner (fingerprint + probe)
├── payloads/
│   ├── xss.txt                # OWASP XSS test vectors
│   ├── sqli.txt               # OWASP SQLi test vectors
│   └── loader.py              # Loads and applies mutations
├── reports/
│   ├── json_report.py
│   └── html_report.py
├── cli/
│   └── commands.py            # Typer CLI
├── utils/
│   ├── logger.py              # Rich-backed logger
│   └── headers.py             # User-agent pool + header helpers
├── tests/
│   ├── test_fingerprints.py
│   ├── test_mutations.py
│   └── test_analyzer.py
├── config.yaml
├── requirements.txt
└── main.py
```

---

## Running Tests

```bash
pip install pytest pytest-asyncio
pytest tests/ -v
```

---

## Extending

**Add a new WAF detector:**
1. Create `core/fingerprints/mywaf.py` extending `BaseDetector`
2. Implement `vendor` and `score(response, body)`
3. Register it in `core/classifiers/orchestrator.py`

**Add new payloads:**
- Append lines to `payloads/xss.txt` or `payloads/sqli.txt`
- Lines starting with `#` are treated as comments

**Add a new mutation technique:**
- Add a static method to `Encoder` or `Obfuscator`
- Register the `(MutationKind, fn)` tuple in `payloads/loader.py`'s pipeline
