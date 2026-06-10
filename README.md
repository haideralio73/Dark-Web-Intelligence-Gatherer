# Dark Web Intelligence Gatherer

**Automated reconnaissance tool that monitors .onion services for leaked credentials, ransomware announcements, and data dumps — routed through Tor.**

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Features

- **Tor routing** — all traffic goes through SOCKS5 (`127.0.0.1:9050`)
- **38 sources** included — ransomware blogs, paste sites, forums, threat intel feeds, SecureDrop instances, stable .onion services (Facebook, BBC, DuckDuckGo, ProtonMail, etc.)
- **Pattern extraction** — emails, domains, credentials (`email:password`), crypto addresses, API keys, IPs, hashes (MD5/SHA1/SHA256)
- **Keyword matching** — exact match + regex + fuzzy matching (`difflib`/`python-Levenshtein`) with confidence scoring
- **SQLite persistence** — SHA-256 deduplication so you never store the same finding twice
- **Daemon mode** — continuous polling (default every 6 hours), delta-only logging
- **HTML reports** — self-contained dashboard with Chart.js timeline, colour-coded severity
- **Webhook alerts** — POST JSON payloads for new critical/high findings (Slack, Discord, custom)
- **WHOIS enrichment** — domain age checks, flags registrations under 30 days
- **OTX enrichment** — optional AlienVault OTX indicator lookup (auto-disabled if no API key)
- **Circuit breaker** — backs off from unresponsive sources automatically
- **Graceful shutdown** — handles SIGINT/SIGTERM cleanly

---

## Requirements

| Dependency | Why |
|---|---|
| **Tor** (running locally) | Routes traffic to .onion sites |
| Python 3.10+ | Type hints, dataclasses |

---

## Setup

### 1. Install Tor

**Windows** — Download [Tor Browser](https://www.torproject.org/download/) — the `tor.exe` inside the Browser folder is all you need.

**Linux** — `sudo apt install tor && sudo systemctl start tor`

### 2. Start Tor

**Windows:**
```powershell
# Navigate to your Tor installation
cd D:\Tor Browser\Browser\TorBrowser\Tor
.\tor.exe
```
Wait until you see `Bootstrapped 100% (done): Done` in the log. Keep this window open.

**Linux:**
```bash
sudo systemctl start tor
journalctl -u tor --follow  # watch bootstrap progress
```

Tor will listen on `127.0.0.1:9050` by default.

> **Can't connect?** Your ISP may be blocking Tor. Try [Snowflake bridges](https://tb-manual.torproject.org/bridges/) — edit your `torrc`:
> ```
> UseBridges 1
> ClientTransportPlugin snowflake exec C:\path\to\lyrebird.exe
> Bridge snowflake
> ```

### 3. Install Python dependencies

```bash
pip install -r requirements.txt
```

---

## Usage

```bash
python dark_intel.py --keywords "yourcompany.com,credentials,leak" [options]
```

### Arguments

| Argument | Default | Description |
|---|---|---|
| `--keywords` | **required** | Comma-separated keywords to monitor |
| `--depth` | `2` | Crawl depth per source |
| `--output` | _(stdout)_ | JSON or HTML report path (`report.json` or `report.html`) |
| `--daemon` | off | Run in persistent polling mode |
| `--interval` | `21600` (6h) | Polling interval in seconds (daemon mode) |
| `--config` | `config.json` | Path to configuration file |
| `--sources` | `sources.json` | Path to sources list |
| `--verbose` | off | Enable debug logging |

### Examples

```bash
# One-shot scan
python dark_intel.py --keywords "acme,credentials,leak" --depth 2 --output report.json

# HTML dashboard with timeline chart
python dark_intel.py --keywords "acme,breach" --depth 1 --output report.html

# Daemon mode — runs forever, polls every hour
python dark_intel.py --keywords "acme" --daemon --interval 3600
```

---

## Output

- **`dark_intel.db`** — SQLite database with all findings (queryable)
- **JSON report** — machine-readable findings with severity, confidence, tags
- **HTML report** — self-contained dashboard with Chart.js timeline, colour-coded severity badges:

| Severity | Colour | Trigger |
|---|---|---|
| Critical | Red | Direct credential leak (`email:password` found) |
| High | Orange | Exact keyword match on ransomware blog |
| Medium | Yellow | Fuzzy match or regex match |
| Low | Grey | Low-confidence fuzzy match |
| Info | Teal | General informational finding |

---

## Configuration

Edit `config.json` to customise:

```json
{
  "tor": { "proxy_port": 9050 },
  "crawler": { "max_pages_per_source": 100, "page_timeout": 30 },
  "matching": { "fuzzy_threshold": 0.75 },
  "daemon": { "interval_seconds": 21600 },
  "alerts": { "webhook_url": "https://hooks.slack.com/..." },
  "enrichment": {
    "otx_api_key": null,
    "whois_lookup": true,
    "domain_age_threshold_days": 30
  }
}
```

---

## Files to Upload to GitHub

```
dark_intel.py          # Main tool (standalone — run this)
config.json            # Default configuration
sources.json           # 38 .onion sources to monitor
requirements.txt       # Python dependencies
README.md              # This file
```

---

## Architecture

```
TorSessionManager   → SOCKS5 proxy + circuit breaker per host
CrawlerEngine       → Depth-limited BFS with HTML parsing
PatternExtractor    → Regex extraction (emails, creds, hashes, crypto, IPs)
KeywordMatcher      → Exact + regex + fuzzy scoring
DatabaseManager     → SQLite + SHA-256 dedup
EnrichmentService   → WHOIS domain age + OTX indicator lookup
AlertManager        → Webhook POST alerts
ReportGenerator     → Jinja2 HTML + Chart.js
DarkIntelApp        → Orchestrator — threading, signal handling, daemon loop
```

---

## License

MIT
