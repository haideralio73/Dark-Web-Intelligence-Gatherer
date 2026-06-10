#!/usr/bin/env python3
"""
Dark Web Intelligence Gatherer — Autonomous .onion monitoring toolkit.

Continuously monitors onion services for leaked credentials, ransomware
announcements, and data dumps. Operates exclusively over Tor with free,
self-hosted resources.

Classes
-------
TorSessionManager
    Manhes SOCKS5 Tor proxy connections with circuit isolation.
CircuitBreaker
    Prevents hammering unresponsive sources.
PatternExtractor
    Extracts emails, domains, credential pairs, hashes, and crypto
    addresses from raw text.
KeywordMatcher
    Scores content against target keywords using exact, regex, and
    fuzzy matching.
DatabaseManager
    SQLite persistence with SHA-256 deduplication.
CrawlerEngine
    Depth-limited BFS crawler with retry and back-off.
EnrichmentService
    OTX indicator lookup and WHOIS domain-age checks.
AlertManager
    Delta-based webhook push alerts.
ReportGenerator
    Self-contained HTML report via Jinja2 + Chart.js.

Examples
--------
One-shot scan ::
    python dark_intel.py --keywords "acme.com,credentials,leak" \\
        --depth 2 --output report.json

Daemon mode  ::
    python dark_intel.py --keywords "acme.com" --daemon \\
        --interval 21600

HTML report  ::
    python dark_intel.py --keywords "example" --depth 1 \\
        --output report.html
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import queue
import re
import signal
import socket
import sqlite3
import sys
import threading
import time
import traceback
import warnings
from abc import ABC, abstractmethod
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from difflib import SequenceMatcher
from enum import Enum, auto
from html import escape
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urljoin, urlparse, urlunparse
from xml.etree import ElementTree

# ---------------------------------------------------------------------------
# Third-party imports  (graceful degradation for optional packages)
# ---------------------------------------------------------------------------
_HAS_BEAUTIFULSOUP = False
_HAS_JINJA2 = False
_HAS_SOCKS = False

try:
    import bs4
    _HAS_BEAUTIFULSOUP = True
except ImportError:
    _HAS_BEAUTIFULSOUP = False

try:
    import jinja2
    _HAS_JINJA2 = True
except ImportError:
    _HAS_JINJA2 = False

try:
    import socks
    import socket as _socket
    _HAS_SOCKS = True
except ImportError:
    _HAS_SOCKS = False

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    requests = None  # type: ignore
    HTTPAdapter = None  # type: ignore
    Retry = None  # type: ignore

try:
    from Levenshtein import ratio as _lev_ratio
except ImportError:
    _lev_ratio = None  # type: ignore

# OTX SDK is optional; we import lazily inside the enrichment class.

warnings.filterwarnings("ignore", category=UserWarning, module="urllib3")

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("dark_intel")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_CONFIG_PATH = Path("config.json")
DEFAULT_SOURCES_PATH = Path("sources.json")
DEFAULT_DB_PATH = Path("dark_intel.db")
DEFAULT_OUTPUT_DIR = Path("reports")
DEFAULT_INTERVAL = 21_600  # 6 hours
DEFAULT_DEPTH = 2
MAX_RESPONSE_BYTES = 2 * 1024 * 1024  # 2 MB
WHOIS_IANA_HOST = "whois.iana.org"
WHOIS_PORT = 43
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0"
)

# Regex patterns (compiled once)
RE_EMAIL = re.compile(
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", re.IGNORECASE
)
RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:onion|com|org|net|int|edu|gov|mil|io|co|ai|app|dev|xyz|info|biz"
    r"|name|pro|me|eu|ru|cn|de|uk|jp|fr|br|au|ca|in|nl|se|no|fi|dk|pl|it"
    r"|es|ch|at|be|cz|sk|hu|ro|bg|gr|pt|il|kr|tw|hk|sg|my|th|vn|ph|id"
    r"|mx|ar|cl|co|za|ng|ke|eg|sa|ae|tr|pk|bd|lk|np|nz|ie)\b",
    re.IGNORECASE,
)
RE_CREDENTIAL = re.compile(
    r"(?P<user>[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"
    r"\s*[:;]\s*(?P<pass>\S+)",
    re.IGNORECASE,
)
RE_BTC_ADDRESS = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
RE_ETH_ADDRESS = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
RE_SHA256 = re.compile(r"\b[A-Fa-f0-9]{64}\b")
RE_SHA1 = re.compile(r"\b[A-Fa-f0-9]{40}\b")
RE_MD5 = re.compile(r"\b[A-Fa-f0-9]{32}\b")
RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
RE_API_KEY = re.compile(
    r"(?i)(?:api[_-]?key|apikey|secret|token|bearer)\s*[:=]\s*['\"]?"
    r"([a-zA-Z0-9_\-]{16,64})['\"]?"
)

# Severity colours for HTML reports
SEVERITY_COLOUR = {
    "critical": "#dc3545",
    "high": "#fd7e14",
    "medium": "#ffc107",
    "low": "#6c757d",
    "info": "#17a2b8",
}


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------
class Severity(Enum):
    """Severity rating for a finding."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SourceType(Enum):
    """Type of intelligence source."""

    ONION = "onion"
    CLEARWEB = "clearweb"


class MatchType(Enum):
    """How a keyword matched against content."""

    EXACT = auto()
    REGEX = auto()
    FUZZY = auto()


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class Source:
    """A monitored intelligence source."""

    name: str
    url: str
    category: str
    type: str = "onion"
    enabled: bool = True
    clearweb_mirror: Optional[str] = None


@dataclass
class CrawlResult:
    """Result from crawling a single page."""

    url: str
    status_code: int
    content_type: str
    raw_text: str
    links: List[str] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class Finding:
    """A single intelligence finding."""

    source_url: str
    snippet: str
    keyword: str
    match_type: MatchType
    confidence: float
    tags: List[str] = field(default_factory=list)
    severity: Severity = Severity.MEDIUM
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    extracted_emails: List[str] = field(default_factory=list)
    extracted_domains: List[str] = field(default_factory=list)
    extracted_credentials: List[Tuple[str, str]] = field(default_factory=list)
    extracted_hashes: List[str] = field(default_factory=list)
    extracted_crypto: List[str] = field(default_factory=list)

    @property
    def dedup_hash(self) -> str:
        """SHA-256 of snippet + source_url for deduplication."""
        raw = (self.snippet.strip() + self.source_url).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()


@dataclass
class ScanReport:
    """Aggregated results from a scan cycle."""

    scan_id: str = field(default_factory=lambda: hashlib.sha256(
        str(time.time()).encode()
    ).hexdigest()[:12])
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    total_sources: int = 0
    sources_ok: int = 0
    sources_failed: int = 0
    pages_crawled: int = 0
    findings: List[Finding] = field(default_factory=list)
    new_findings: int = 0


# ---------------------------------------------------------------------------
# CircuitBreaker
# ---------------------------------------------------------------------------
class CircuitBreaker:
    """Simple circuit-breaker for a single upstream host.

    Parameters
    ----------
    threshold : int
        Consecutive failures before opening the circuit.
    reset_seconds : float
        Seconds to wait before trying again (half-open).
    """

    def __init__(self, threshold: int = 5, reset_seconds: float = 300.0) -> None:
        self._threshold = threshold
        self._reset_seconds = reset_seconds
        self._failures: int = 0
        self._last_failure_time: float = 0.0
        self._lock = threading.Lock()
        self._open = False

    @property
    def is_open(self) -> bool:
        """Check whether the circuit is currently open."""
        with self._lock:
            if not self._open:
                return False
            if time.time() - self._last_failure_time > self._reset_seconds:
                self._open = False
                self._failures = 0
                return False
            return True

    def record_success(self) -> None:
        """Reset failure count on success."""
        with self._lock:
            self._failures = 0
            self._open = False

    def record_failure(self) -> None:
        """Increment failure counter; open circuit if threshold reached."""
        with self._lock:
            self._failures += 1
            self._last_failure_time = time.time()
            if self._failures >= self._threshold:
                self._open = True
                logger.warning("Circuit breaker OPEN for host")
                return
            logger.debug("Circuit breaker: %d/%d failures", self._failures, self._threshold)


# ---------------------------------------------------------------------------
# TorSessionManager
# ---------------------------------------------------------------------------
class TorSessionManager:
    """Manages a requests session routed through a local Tor SOCKS5 proxy.

    Parameters
    ----------
    proxy_host : str
        SOCKS proxy host (default 127.0.0.1).
    proxy_port : int
        SOCKS proxy port (default 9050).
    timeout : int
        Default request timeout in seconds.
    max_retries : int
        Number of retries for failed requests.
    """

    def __init__(
        self,
        proxy_host: str = "127.0.0.1",
        proxy_port: int = 9050,
        timeout: int = 30,
        max_retries: int = 3,
    ) -> None:
        self._proxy_host = proxy_host
        self._proxy_port = proxy_port
        self._timeout = timeout
        self._max_retries = max_retries
        self._session: Optional[requests.Session] = None
        self._circuit_breakers: Dict[str, CircuitBreaker] = defaultdict(
            lambda: CircuitBreaker()
        )

    # ------------------------------------------------------------------
    @property
    def session(self) -> requests.Session:
        if self._session is None:
            self._session = self._build_session()
        return self._session

    def _build_session(self) -> requests.Session:
        """Create a requests session routed through Tor."""
        sess = requests.Session()
        sess.headers.update({"User-Agent": USER_AGENT})
        sess.proxies = {
            "http": f"socks5h://{self._proxy_host}:{self._proxy_port}",
            "https": f"socks5h://{self._proxy_host}:{self._proxy_port}",
        }
        sess.verify = False

        retry_strategy = Retry(
            total=self._max_retries,
            backoff_factor=1.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods={"GET", "POST"},
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        sess.mount("http://", adapter)
        sess.mount("https://", adapter)
        return sess

    def get_tor_ip(self) -> str:
        """Check what IP address Tor is currently presenting."""
        try:
            resp = self.session.get(
                "https://check.torproject.org/api/ip",
                timeout=self._timeout,
            )
            data = resp.json()
            return data.get("IP", "unknown")
        except Exception as exc:
            logger.warning("Could not check Tor IP: %s", exc)
            return "unknown"

    def fetch(
        self, url: str, timeout: Optional[int] = None
    ) -> Tuple[Optional[bytes], Optional[str]]:
        """Fetch a URL through Tor with circuit-breaker awareness.

        Parameters
        ----------
        url : str
            Target URL.
        timeout : int or None
            Request-level timeout (overrides default).

        Returns
        -------
        Tuple[bytes or None, str or None]
            (response_body, error_message)
        """
        hostname = urlparse(url).hostname or url
        cb = self._circuit_breakers[hostname]
        if cb.is_open:
            logger.warning("Skipping %s — circuit breaker open", hostname)
            return None, "circuit_breaker_open"

        t_o = timeout if timeout is not None else self._timeout
        for attempt in range(self._max_retries + 1):
            try:
                resp = self.session.get(url, timeout=t_o, stream=True)
                content = resp.raw.read(MAX_RESPONSE_BYTES + 1)
                if len(content) > MAX_RESPONSE_BYTES:
                    logger.warning("Response from %s exceeded 2 MB, truncated", url)

                cb.record_success()
                return content[:MAX_RESPONSE_BYTES], None

            except requests.exceptions.Timeout:
                cb.record_failure()
                err = f"timeout (attempt {attempt + 1})"
                if attempt < self._max_retries:
                    wait = 2 ** attempt
                    logger.debug("Retrying %s after %ds: %s", url, wait, err)
                    time.sleep(wait)
                else:
                    logger.error("Failed to fetch %s: %s", url, err)
                    return None, err

            except requests.exceptions.ConnectionError as exc:
                cb.record_failure()
                err = f"connection_error: {exc}"
                if attempt < self._max_retries:
                    wait = 2 ** attempt
                    logger.debug("Retrying %s after %ds: %s", url, wait, err)
                    time.sleep(wait)
                else:
                    logger.error("Failed to fetch %s: %s", url, err)
                    return None, err

            except Exception as exc:
                cb.record_failure()
                err = str(exc)
                logger.error("Failed to fetch %s: %s", url, err)
                return None, err

        return None, "max_retries_exceeded"

    def close(self) -> None:
        if self._session is not None:
            self._session.close()
            self._session = None


# ---------------------------------------------------------------------------
# PatternExtractor
# ---------------------------------------------------------------------------
class PatternExtractor:
    """Extract structured indicators from raw text using regex patterns."""

    @staticmethod
    def extract_emails(text: str) -> List[str]:
        """Return unique email addresses found in *text*."""
        return sorted(set(m.group(0) for m in RE_EMAIL.finditer(text)))

    @staticmethod
    def extract_domains(text: str) -> List[str]:
        """Return unique domain names found in *text*."""
        seen: Set[str] = set()
        for m in RE_DOMAIN.finditer(text):
            domain = m.group(0).lower()
            # skip onion addresses extracted from link contexts
            seen.add(domain)
        return sorted(seen)

    @staticmethod
    def extract_credentials(text: str) -> List[Tuple[str, str]]:
        """Return (email, password) pairs found in *text*."""
        pairs: List[Tuple[str, str]] = []
        for m in RE_CREDENTIAL.finditer(text):
            email = m.group("user").strip().lower()
            password = m.group("pass").strip()
            if len(password) < 128:
                pairs.append((email, password))
        return pairs

    @staticmethod
    def extract_hashes(text: str) -> List[str]:
        """Return unique cryptographic hash values."""
        found: Set[str] = set()
        for pat in (RE_MD5, RE_SHA1, RE_SHA256):
            for m in pat.finditer(text):
                found.add(m.group(0))
        return sorted(found)

    @staticmethod
    def extract_crypto_addresses(text: str) -> List[str]:
        """Return unique cryptocurrency addresses."""
        found: Set[str] = set()
        for m in RE_BTC_ADDRESS.finditer(text):
            found.add(m.group(0))
        for m in RE_ETH_ADDRESS.finditer(text):
            found.add(m.group(0))
        return sorted(found)

    @staticmethod
    def extract_api_keys(text: str) -> List[str]:
        """Return potential API keys / secrets."""
        return sorted(set(
            m.group(1) for m in RE_API_KEY.finditer(text)
        ))

    @staticmethod
    def extract_ips(text: str) -> List[str]:
        """Return unique IPv4 addresses (private ranges excluded optionally)."""
        return sorted(set(m.group(0) for m in RE_IPV4.finditer(text)))

    @classmethod
    def extract_all(cls, text: str) -> Dict[str, List[str]]:
        """Convenience: run all extractors and return a dict of results."""
        return {
            "emails": cls.extract_emails(text),
            "domains": cls.extract_domains(text),
            "credentials": [
                f"{e}:{p}" for e, p in cls.extract_credentials(text)
            ],
            "hashes": cls.extract_hashes(text),
            "crypto": cls.extract_crypto_addresses(text),
            "api_keys": cls.extract_api_keys(text),
            "ips": cls.extract_ips(text),
        }


# ---------------------------------------------------------------------------
# KeywordMatcher
# ---------------------------------------------------------------------------
class KeywordMatcher:
    """Score content against a list of target keywords.

    Parameters
    ----------
    keywords : list of str
        Keywords to search for.
    case_sensitive : bool
        Whether matching is case-sensitive.
    fuzzy_threshold : float
        Minimum similarity ratio (0-1) for fuzzy matching.
    enable_exact : bool
        Enable exact substring matching.
    enable_regex : bool
        Enable regex pattern matching.
    enable_fuzzy : bool
        Enable fuzzy matching via difflib.
    """

    def __init__(
        self,
        keywords: List[str],
        case_sensitive: bool = False,
        fuzzy_threshold: float = 0.75,
        enable_exact: bool = True,
        enable_regex: bool = True,
        enable_fuzzy: bool = True,
    ) -> None:
        self._keywords = keywords
        self._case_sensitive = case_sensitive
        self._fuzzy_threshold = fuzzy_threshold
        self._enable_exact = enable_exact
        self._enable_regex = enable_regex
        self._enable_fuzzy = enable_fuzzy
        self._regex_patterns: List[re.Pattern] = []
        self._compile_regex()

    def _compile_regex(self) -> None:
        for kw in self._keywords:
            try:
                self._regex_patterns.append(re.compile(kw, re.I if not self._case_sensitive else 0))
            except re.error:
                logger.debug("Keyword '%s' is not valid regex, skipping pattern", kw)

    def score(
        self,
        text: str,
        snippet: str,
    ) -> List[Tuple[str, MatchType, float]]:
        """Score *snippet* (and *text* for regex) against all keywords.

        Returns
        -------
        list of (keyword, match_type, confidence)
        """
        results: List[Tuple[str, MatchType, float]] = []
        src = snippet if self._case_sensitive else snippet.lower()
        src_text = text if self._case_sensitive else text.lower()

        for kw in self._keywords:
            kw_comp = kw if self._case_sensitive else kw.lower()
            best_conf = 0.0
            best_type = MatchType.FUZZY

            # --- exact ---
            if self._enable_exact and kw_comp in src:
                conf = 1.0
                if kw_comp == src.strip().lower():
                    conf = 1.0
                elif kw_comp in src:
                    conf = 0.95
                if conf > best_conf:
                    best_conf = conf
                    best_type = MatchType.EXACT

            # --- regex ---
            if self._enable_regex:
                for pat in self._regex_patterns:
                    m = pat.search(src_text)
                    if m:
                        conf = 1.0
                        if conf > best_conf:
                            best_conf = conf
                            best_type = MatchType.REGEX

            # --- fuzzy ---
            if self._enable_fuzzy and best_conf < 1.0:
                ratio = self._fuzzy_ratio(kw_comp, src)
                if ratio >= self._fuzzy_threshold and ratio > best_conf:
                    best_conf = ratio
                    best_type = MatchType.FUZZY

            if best_conf > 0:
                results.append((kw, best_type, round(best_conf, 4)))

        return results

    @staticmethod
    def _fuzzy_ratio(a: str, b: str) -> float:
        """Return similarity ratio between two strings."""
        if _lev_ratio is not None:
            return _lev_ratio(a, b)
        return SequenceMatcher(None, a, b).ratio()


# ---------------------------------------------------------------------------
# DatabaseManager
# ---------------------------------------------------------------------------
class DatabaseManager:
    """SQLite persistence layer with SHA-256 deduplication.

    Parameters
    ----------
    db_path : str or Path
        Path to the SQLite database file.
    """

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS findings (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp     TEXT    NOT NULL,
        source_url    TEXT    NOT NULL,
        snippet       TEXT    NOT NULL,
        confidence    REAL    NOT NULL DEFAULT 0.0,
        tags          TEXT    NOT NULL DEFAULT '[]',
        severity      TEXT    NOT NULL DEFAULT 'medium',
        keyword       TEXT,
        match_type    TEXT,
        dedup_hash    TEXT    NOT NULL UNIQUE,
        metadata      TEXT    DEFAULT '{}',
        created_at    TEXT    DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_findings_timestamp ON findings(timestamp);
    CREATE INDEX IF NOT EXISTS idx_findings_severity  ON findings(severity);
    CREATE INDEX IF NOT EXISTS idx_findings_source    ON findings(source_url);
    CREATE INDEX IF NOT EXISTS idx_findings_keyword   ON findings(keyword);
    CREATE INDEX IF NOT EXISTS idx_dedup_hash         ON findings(dedup_hash);

    CREATE TABLE IF NOT EXISTS crawl_log (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        source_url    TEXT    NOT NULL,
        status        TEXT    NOT NULL,
        pages_count   INTEGER DEFAULT 0,
        findings_count INTEGER DEFAULT 0,
        duration_ms   INTEGER DEFAULT 0,
        error         TEXT,
        timestamp     TEXT    DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS enrichment_cache (
        indicator     TEXT    PRIMARY KEY,
        data          TEXT    NOT NULL,
        source        TEXT    NOT NULL,
        fetched_at    TEXT    DEFAULT (datetime('now'))
    );
    """

    def __init__(self, db_path: Union[str, Path] = "dark_intel.db") -> None:
        self._db_path = Path(db_path)
        self._local = threading.local()
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        """Ensure schema exists on the primary thread."""
        conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.row_factory = sqlite3.Row
        conn.executescript(self._SCHEMA)
        conn.commit()
        conn.close()

    def _get_conn(self) -> sqlite3.Connection:
        """Get a thread-local connection."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(
                str(self._db_path), check_same_thread=False
            )
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA synchronous=NORMAL")
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    def close(self) -> None:
        """Close all connections on all threads (best effort)."""
        if hasattr(self._local, "conn") and self._local.conn is not None:
            try:
                self._local.conn.close()
            except Exception:
                pass
            self._local.conn = None

    def is_duplicate(self, dedup_hash: str) -> bool:
        conn = self._get_conn()
        cur = conn.execute(
            "SELECT 1 FROM findings WHERE dedup_hash = ?", (dedup_hash,)
        )
        return cur.fetchone() is not None

    def store_finding(self, finding: Finding) -> bool:
        dh = finding.dedup_hash
        if self.is_duplicate(dh):
            return False

        tags_json = json.dumps(finding.tags)
        metadata = {
            "emails": finding.extracted_emails,
            "domains": finding.extracted_domains,
            "credentials": finding.extracted_credentials,
            "hashes": finding.extracted_hashes,
            "crypto": finding.extracted_crypto,
        }

        conn = self._get_conn()
        with self._lock:
            conn.execute(
                """INSERT INTO findings
                   (timestamp, source_url, snippet, confidence, tags, severity,
                    keyword, match_type, dedup_hash, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    finding.timestamp.isoformat(),
                    finding.source_url,
                    finding.snippet[:2000],
                    finding.confidence,
                    tags_json,
                    finding.severity.value,
                    finding.keyword,
                    finding.match_type.name.lower(),
                    dh,
                    json.dumps(metadata),
                ),
            )
            conn.commit()
        return True

    def store_findings_batch(self, findings: List[Finding]) -> int:
        count = 0
        for f in findings:
            if self.store_finding(f):
                count += 1
        return count

    def log_crawl(
        self,
        source_url: str,
        status: str,
        pages_count: int = 0,
        findings_count: int = 0,
        duration_ms: int = 0,
        error: Optional[str] = None,
    ) -> None:
        conn = self._get_conn()
        with self._lock:
            conn.execute(
                """INSERT INTO crawl_log
                   (source_url, status, pages_count, findings_count, duration_ms, error)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (source_url, status, pages_count, findings_count, duration_ms, error),
            )
            conn.commit()

    def get_recent_findings(
        self,
        limit: int = 500,
        severity: Optional[str] = None,
        since: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        conn = self._get_conn()
        query = "SELECT * FROM findings WHERE 1=1"
        params: List[Any] = []
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if since:
            query += " AND timestamp >= ?"
            params.append(since.isoformat())
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_statistics(self) -> Dict[str, Any]:
        conn = self._get_conn()
        stats: Dict[str, Any] = {}
        stats["total_findings"] = conn.execute(
            "SELECT COUNT(*) FROM findings"
        ).fetchone()[0]
        stats["total_sources_scanned"] = conn.execute(
            "SELECT COUNT(DISTINCT source_url) FROM crawl_log WHERE status='ok'"
        ).fetchone()[0]
        sev_rows = conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM findings GROUP BY severity"
        ).fetchall()
        stats["severity"] = {r["severity"]: r["cnt"] for r in sev_rows}
        stats["last_scan"] = conn.execute(
            "SELECT MAX(timestamp) FROM crawl_log"
        ).fetchone()[0]
        return stats


# ---------------------------------------------------------------------------
# EnrichmentService
# ---------------------------------------------------------------------------
class EnrichmentService:
    """Optional enrichment via OTX API and WHOIS lookups.

    Parameters
    ----------
    otx_api_key : str or None
        AlienVault OTX API key. When None, OTX enrichment is disabled.
    do_whois : bool
        Whether to perform WHOIS lookups for discovered domains.
    """

    def __init__(
        self,
        otx_api_key: Optional[str] = None,
        do_whois: bool = True,
        domain_age_threshold_days: int = 30,
    ) -> None:
        self._otx_key = otx_api_key
        self._do_whois = do_whois
        self._domain_age_threshold = domain_age_threshold_days
        self._otx_client: Any = None
        self._cache: Dict[str, Any] = {}

        if self._otx_key:
            try:
                from OTXv2 import OTXv2
                self._otx_client = OTXv2(self._otx_key)
                logger.info("OTX enrichment initialised")
            except ImportError:
                logger.warning(
                    "OTX-Python-SDK not installed; OTX enrichment disabled"
                )
                self._otx_client = None
            except Exception as exc:
                logger.warning("OTX init failed: %s; OTX disabled", exc)
                self._otx_client = None

    # ------------------------------------------------------------------
    # OTX
    # ------------------------------------------------------------------
    def otx_query(self, indicator: str, indicator_type: str = "domain") -> Dict[str, Any]:
        """Query OTX for intelligence on an indicator.

        Parameters
        ----------
        indicator : str
            The indicator value.
        indicator_type : str
            One of ``domain``, ``ipv4``, ``hostname``, ``url``, ``hash``.

        Returns
        -------
        dict
            Pulse information or empty dict on failure.
        """
        if self._otx_client is None:
            return {}
        cache_key = f"otx:{indicator}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        try:
            result = self._otx_client.get_indicator_details_by_section(
                indicator_type, indicator, "general"
            )
            self._cache[cache_key] = result
            return result
        except Exception as exc:
            logger.debug("OTX query failed for %s: %s", indicator, exc)
            return {}

    # ------------------------------------------------------------------
    # WHOIS
    # ------------------------------------------------------------------
    def whois_lookup(self, domain: str) -> Dict[str, Any]:
        """Perform raw WHOIS lookup via iana.org.

        Parameters
        ----------
        domain : str
            Domain name to query.

        Returns
        -------
        dict
            Parsed WHOIS data including ``creation_date`` and ``age_days``.
        """
        cache_key = f"whois:{domain}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        result: Dict[str, Any] = {
            "domain": domain,
            "creation_date": None,
            "registrar": None,
            "age_days": None,
            "is_recent": None,
        }

        if not self._do_whois:
            return result

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((WHOIS_IANA_HOST, WHOIS_PORT))
            sock.sendall(f"{domain}\r\n".encode())

            data = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 65536:
                    break
            sock.close()

            text = data.decode("utf-8", errors="replace")

            # Try to find creation date
            date_patterns = [
                r"Creation Date:\s*(.+)",
                r"created:\s*(.+)",
                r"Registration Date:\s*(.+)",
                r"Domain Registration Date:\s*(.+)",
            ]
            for pat in date_patterns:
                m = re.search(pat, text, re.IGNORECASE)
                if m:
                    date_str = m.group(1).strip()
                    try:
                        from dateparser import parse as dateparse
                        dt = dateparse(date_str)
                        if dt is None:
                            dt = datetime.now(timezone.utc)
                        elif dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        result["creation_date"] = dt.isoformat()
                        age = (datetime.now(timezone.utc) - dt).days
                        result["age_days"] = age
                        result["is_recent"] = age < self._domain_age_threshold
                    except Exception:
                        pass
                    break

            # Registrar
            reg_pat = r"Registrar:\s*(.+)"
            rm = re.search(reg_pat, text, re.IGNORECASE)
            if rm:
                result["registrar"] = rm.group(1).strip()

        except Exception as exc:
            logger.debug("WHOIS lookup failed for %s: %s", domain, exc)

        self._cache[cache_key] = result
        return result

    def enrich_domains(self, domains: List[str]) -> Dict[str, Dict[str, Any]]:
        """Bulk WHOIS enrichment for a list of domains."""
        results = {}
        for d in domains:
            if d.endswith(".onion"):
                continue
            results[d] = self.whois_lookup(d)
            time.sleep(0.2)  # be polite
        return results

    def enrich_indicators(
        self, ips: List[str], domains: List[str], hashes: List[str]
    ) -> Dict[str, Dict[str, Any]]:
        """Bulk OTX enrichment for lists of indicators."""
        if self._otx_client is None:
            return {}
        results: Dict[str, Dict[str, Any]] = {}
        for d in domains:
            if not d.endswith(".onion"):
                results[d] = self.otx_query(d, "domain")
        for ip in ips:
            results[ip] = self.otx_query(ip, "ipv4")
        for h in hashes:
            results[h] = self.otx_query(h, "hash")
        return results


# ---------------------------------------------------------------------------
# AlertManager
# ---------------------------------------------------------------------------
class AlertManager:
    """Push delta-based alerts via webhook.

    Parameters
    ----------
    webhook_url : str or None
        URL to POST alerts to. Disabled when None.
    """

    def __init__(self, webhook_url: Optional[str] = None) -> None:
        self._webhook_url = webhook_url

    def send_alert(self, finding: Finding) -> bool:
        """Send an alert for a single finding.

        Returns True on success (or if alerts are disabled).
        """
        if not self._webhook_url:
            return True

        payload = {
            "event": "dark_intel_finding",
            "timestamp": finding.timestamp.isoformat(),
            "severity": finding.severity.value,
            "keyword": finding.keyword,
            "confidence": finding.confidence,
            "source_url": finding.source_url,
            "snippet": finding.snippet[:500],
            "tags": finding.tags,
        }

        try:
            import requests
            resp = requests.post(
                self._webhook_url,
                json=payload,
                timeout=10,
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            logger.info("Alert sent for keyword '%s'", finding.keyword)
            return True
        except Exception as exc:
            logger.warning("Failed to send alert: %s", exc)
            return False

    def send_batch_alert(self, findings: List[Finding]) -> int:
        """Send alerts for multiple findings.

        Returns the number of successful deliveries.
        """
        count = 0
        for f in findings:
            if self.send_alert(f):
                count += 1
        return count


# ---------------------------------------------------------------------------
# ReportGenerator
# ---------------------------------------------------------------------------
class ReportGenerator:
    """Generate self-contained HTML reports via Jinja2 and Chart.js.

    Parameters
    ----------
    output_dir : str or Path
        Directory where reports are stored.
    """

    _HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Dark Intel Report — {{ scan_id }}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4/dist/chart.umd.min.js"></script>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
       background: #0d1117; color: #c9d1d9; padding: 24px; }
h1 { color: #58a6ff; margin-bottom: 8px; }
h2 { color: #f0f6fc; margin: 24px 0 12px; }
.meta { color: #8b949e; font-size: 0.9em; margin-bottom: 24px; }
.summary-cards { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 24px; }
.card { background: #161b22; border: 1px solid #30363d; border-radius: 8px;
        padding: 16px 24px; min-width: 140px; }
.card h3 { font-size: 0.8em; color: #8b949e; text-transform: uppercase; }
.card .value { font-size: 2em; font-weight: 700; margin-top: 4px; }
.chart-container { background: #161b22; border: 1px solid #30363d; border-radius: 8px;
                    padding: 20px; margin-bottom: 24px; max-width: 600px; }
table { width: 100%; border-collapse: collapse; background: #161b22;
         border: 1px solid #30363d; border-radius: 8px; overflow: hidden; }
th { background: #21262d; padding: 10px 12px; text-align: left;
     font-size: 0.85em; color: #8b949e; text-transform: uppercase; }
td { padding: 10px 12px; border-top: 1px solid #30363d; font-size: 0.9em; }
tr:hover { background: #1c2128; }
.sev-badge { display: inline-block; padding: 2px 8px; border-radius: 12px;
             font-size: 0.75em; font-weight: 600; color: #fff; }
.snippet { max-width: 400px; overflow: hidden; text-overflow: ellipsis;
           white-space: nowrap; color: #8b949e; font-family: monospace; font-size: 0.85em; }
.tags { display: flex; gap: 4px; flex-wrap: wrap; }
.tag { background: #21262d; padding: 2px 8px; border-radius: 8px;
        font-size: 0.75em; color: #58a6ff; }
.footer { margin-top: 32px; color: #484f58; font-size: 0.8em; text-align: center; }
</style>
</head>
<body>
<h1>Dark Web Intelligence Report</h1>
<p class="meta">
  Report ID: <strong>{{ scan_id }}</strong> &middot;
  Generated: <strong>{{ timestamp }}</strong> &middot;
  Sources: {{ total_sources }} ({{ sources_ok }} ok, {{ sources_failed }} failed) &middot;
  Pages: {{ pages_crawled }} &middot;
  Findings: {{ findings|length }} ({{ new_findings }} new)
</p>

<div class="summary-cards">
  <div class="card"><h3>Critical</h3><div class="value" style="color:#dc3545">{{ severity_counts.critical|default(0) }}</div></div>
  <div class="card"><h3>High</h3><div class="value" style="color:#fd7e14">{{ severity_counts.high|default(0) }}</div></div>
  <div class="card"><h3>Medium</h3><div class="value" style="color:#ffc107">{{ severity_counts.medium|default(0) }}</div></div>
  <div class="card"><h3>Low</h3><div class="value" style="color:#6c757d">{{ severity_counts.low|default(0) }}</div></div>
  <div class="card"><h3>Info</h3><div class="value" style="color:#17a2b8">{{ severity_counts.info|default(0) }}</div></div>
</div>

{% if timeline_labels %}
<div class="chart-container">
  <canvas id="timelineChart"></canvas>
</div>
<script>
(function() {
  const ctx = document.getElementById('timelineChart').getContext('2d');
  new Chart(ctx, {
    type: 'line',
    data: {
      labels: {{ timeline_labels|safe }},
      datasets: [{
        label: 'Findings over time',
        data: {{ timeline_values|safe }},
        borderColor: '#58a6ff',
        backgroundColor: 'rgba(88,166,255,0.1)',
        fill: true,
        tension: 0.3,
      }]
    },
    options: {
      responsive: true,
      plugins: { legend: { labels: { color: '#c9d1d9' } } },
      scales: {
        x: { ticks: { color: '#8b949e' }, grid: { color: '#21262d' } },
        y: { ticks: { color: '#8b949e' }, grid: { color: '#21262d' }, beginAtZero: true }
      }
    }
  });
})();
</script>
{% endif %}

<h2>Findings ({{ findings|length }})</h2>
<table>
<thead><tr>
  <th>Severity</th><th>Keyword</th><th>Confidence</th><th>Source</th><th>Snippet</th><th>Tags</th><th>Timestamp</th>
</tr></thead>
<tbody>
{% for f in findings %}
<tr>
  <td><span class="sev-badge" style="background:{{ sev_colour(f.severity) }}">{{ f.severity }}</span></td>
  <td>{{ f.keyword }}</td>
  <td>{{ "%.0f"|format(f.confidence * 100) }}%</td>
  <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;" title="{{ f.source_url }}">{{ f.source_url }}</td>
  <td class="snippet" title="{{ f.snippet }}">{{ f.snippet[:120] }}{% if f.snippet|length > 120 %}…{% endif %}</td>
  <td><div class="tags">{% for t in f.tags %}<span class="tag">{{ t }}</span>{% endfor %}</div></td>
  <td style="font-size:0.85em;color:#8b949e">{{ f.timestamp[:19] }}</td>
</tr>
{% endfor %}
</tbody>
</table>

<div class="footer">
Dark Web Intelligence Gatherer &mdash; Generated by dark_intel.py
</div>
</body>
</html>
"""

    def __init__(self, output_dir: Union[str, Path] = "reports") -> None:
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._env: Optional[jinja2.Environment] = None
        if _HAS_JINJA2:
            self._env = jinja2.Environment()

    def generate(
        self,
        report: ScanReport,
        output_path: Union[str, Path, None] = None,
    ) -> Optional[Path]:
        """Generate and write an HTML report.

        Parameters
        ----------
        report : ScanReport
            Data to render.
        output_path : str, Path, or None
            Target file path. When None, auto-names under output_dir.

        Returns
        -------
        Path or None
            Path to the written report, or None if Jinja2 is unavailable.
        """
        if not _HAS_JINJA2 or self._env is None:
            logger.warning("Jinja2 not installed; skipping HTML report")
            return None

        from jinja2 import BaseLoader, Environment

        env = Environment()
        env.globals["sev_colour"] = SEVERITY_COLOUR.get

        # Build timeline data
        timeline_map: Dict[str, int] = defaultdict(int)
        for f in report.findings:
            day = f.timestamp.strftime("%Y-%m-%d") if hasattr(f.timestamp, "strftime") else str(f.timestamp)[:10]
            timeline_map[day] += 1

        timeline_labels = json.dumps(sorted(timeline_map.keys()))
        timeline_values = json.dumps([timeline_map[k] for k in sorted(timeline_map.keys())])

        severity_counts = defaultdict(int)
        for f in report.findings:
            severity_counts[f.severity.value if isinstance(f.severity, Severity) else f.severity] += 1

        class FindingProxy:
            def __init__(self, f: Finding) -> None:
                self.severity = f.severity.value if isinstance(f.severity, Severity) else f.severity
                self.keyword = f.keyword
                self.confidence = f.confidence
                self.source_url = f.source_url
                self.snippet = f.snippet
                self.tags = f.tags
                self.timestamp = f.timestamp.isoformat() if isinstance(f.timestamp, datetime) else str(f.timestamp)

        rendered = env.from_string(self._HTML_TEMPLATE).render(
            scan_id=report.scan_id,
            timestamp=report.timestamp.isoformat() if isinstance(report.timestamp, datetime) else str(report.timestamp),
            total_sources=report.total_sources,
            sources_ok=report.sources_ok,
            sources_failed=report.sources_failed,
            pages_crawled=report.pages_crawled,
            findings=[FindingProxy(f) for f in report.findings],
            new_findings=report.new_findings,
            severity_counts=dict(severity_counts),
            timeline_labels=timeline_labels,
            timeline_values=timeline_values,
        )

        if output_path is None:
            fname = f"dark_intel_{report.scan_id}.html"
            output_path = self._output_dir / fname

        out = Path(output_path)
        out.write_text(rendered, encoding="utf-8")
        logger.info("Report written to %s", out.resolve())
        return out


# ---------------------------------------------------------------------------
# CrawlerEngine
# ---------------------------------------------------------------------------
class CrawlerEngine:
    """Depth-limited BFS crawler for Tor/onion and clearweb sources.

    Parameters
    ----------
    session_manager : TorSessionManager
        Pre-configured Tor session manager.
    max_pages : int
        Maximum pages to crawl per source.
    page_timeout : int
        Per-page request timeout.
    min_text_length : int
        Minimum text length (chars) for a page to be processed.
    """

    def __init__(
        self,
        session_manager: TorSessionManager,
        max_pages: int = 100,
        page_timeout: int = 30,
        min_text_length: int = 50,
    ) -> None:
        self._session = session_manager
        self._max_pages = max_pages
        self._timeout = page_timeout
        self._min_text = min_text_length

    def crawl(self, source: Source, depth: int = 1) -> CrawlResult:
        """Crawl a single source URL up to the given depth.

        Parameters
        ----------
        source : Source
            The source definition.
        depth : int
            Maximum crawl depth (0 = page only, no link following).

        Returns
        -------
        CrawlResult
        """
        start_time = time.perf_counter()
        visited: Set[str] = set()
        page_queue: queue.Queue[Tuple[str, int]] = queue.Queue()
        page_queue.put((source.url, 0))

        combined_text: List[str] = []
        all_links: Set[str] = set()
        pages_crawled = 0
        last_error: Optional[str] = None

        while not page_queue.empty() and pages_crawled < self._max_pages:
            url, current_depth = page_queue.get()
            if url in visited:
                continue
            visited.add(url)

            content, error = self._session.fetch(url, timeout=self._timeout)
            if error:
                last_error = error
                logger.debug("Failed %s: %s", url, error)
                continue
            if content is None:
                continue

            pages_crawled += 1
            text, links = self._parse_html(url, content)
            if text:
                combined_text.append(text)

            for link in links:
                all_links.add(link)
                if current_depth < depth and link not in visited:
                    page_queue.put((link, current_depth + 1))

        duration_ms = int((time.perf_counter() - start_time) * 1000)
        full_text = "\n".join(combined_text) if combined_text else ""

        return CrawlResult(
            url=source.url,
            status_code=200 if not last_error else 0,
            content_type="text/html",
            raw_text=full_text,
            links=sorted(all_links),
            error=last_error,
        )

    def _parse_html(
        self, base_url: str, content: bytes
    ) -> Tuple[Optional[str], List[str]]:
        """Parse HTML content, returning (text_content, list_of_links)."""
        # Try to decode
        text: Optional[str] = None
        links: List[str] = []

        try:
            decoded = content.decode("utf-8", errors="replace")
        except Exception:
            decoded = content.decode("latin-1", errors="replace")

        if _HAS_BEAUTIFULSOUP:
            try:
                soup = bs4.BeautifulSoup(decoded, "lxml")
                # Remove script/style
                for tag in soup(["script", "style", "noscript", "meta", "link"]):
                    tag.decompose()
                text = soup.get_text(separator=" ", strip=True)
                if len(text) < self._min_text:
                    text = None

                # Extract links
                for a_tag in soup.find_all("a", href=True):
                    href = a_tag["href"]
                    absolute = urljoin(base_url, href)
                    parsed = urlparse(absolute)
                    if parsed.scheme in ("http", "https"):
                        normalized = urlunparse(
                            (parsed.scheme, parsed.netloc, parsed.path, "", "", "")
                        )
                        links.append(normalized)
            except Exception:
                text = None
        else:
            # Fallback: rough text extraction via regex
            text = re.sub(r"<[^>]+>", " ", decoded)
            text = re.sub(r"\s+", " ", text).strip()
            if len(text) < self._min_text:
                text = None

            # Basic link extraction
            for m in re.finditer(r'href=["\'](https?://[^"\']+)["\']', decoded, re.I):
                links.append(m.group(1))

        # Deduplicate links
        seen: Set[str] = set()
        unique_links: List[str] = []
        for lnk in links:
            if lnk not in seen:
                seen.add(lnk)
                unique_links.append(lnk)

        return text, unique_links[:200]  # cap links per page


# ---------------------------------------------------------------------------
# DarkIntelApp — Orchestrator
# ---------------------------------------------------------------------------
class DarkIntelApp:
    """Main application orchestrator.

    Coordinates crawling, pattern extraction, keyword matching, persistence,
    enrichment, alerting, and reporting.
    """

    def __init__(
        self,
        config_path: Union[str, Path] = "config.json",
        sources_path: Union[str, Path] = "sources.json",
    ) -> None:
        self._config_path = Path(config_path)
        self._sources_path = Path(sources_path)
        self._config: Dict[str, Any] = self._load_config()
        self._sources: List[Source] = self._load_sources()

        self._tor_mgr = TorSessionManager(
            proxy_host=self._config.get("tor", {}).get("proxy_host", "127.0.0.1"),
            proxy_port=self._config.get("tor", {}).get("proxy_port", 9050),
            timeout=self._config.get("crawler", {}).get("page_timeout", 30),
            max_retries=self._config.get("crawler", {}).get("max_retries", 3),
        )

        self._db = DatabaseManager(
            db_path=self._config.get("database", {}).get("path", "dark_intel.db"),
        )

        match_cfg = self._config.get("matching", {})
        self._keywords: List[str] = []

        crawl_cfg = self._config.get("crawler", {})
        self._engine = CrawlerEngine(
            session_manager=self._tor_mgr,
            max_pages=crawl_cfg.get("max_pages_per_source", 100),
            page_timeout=crawl_cfg.get("page_timeout", 30),
        )

        self._extractor = PatternExtractor()

        enrich_cfg = self._config.get("enrichment", {})
        self._enrichment = EnrichmentService(
            otx_api_key=enrich_cfg.get("otx_api_key"),
            do_whois=enrich_cfg.get("whois_lookup", True),
            domain_age_threshold_days=enrich_cfg.get("domain_age_threshold_days", 30),
        )

        alert_cfg = self._config.get("alerts", {})
        self._alerts = AlertManager(
            webhook_url=alert_cfg.get("webhook_url"),
        )

        self._report_gen = ReportGenerator(
            output_dir=self._config.get("reporting", {}).get("output_dir", "reports"),
        )

        self._running = threading.Event()
        self._running.set()

    # ------------------------------------------------------------------
    # Config / Source loading
    # ------------------------------------------------------------------
    def _load_config(self) -> Dict[str, Any]:
        path = self._config_path
        if not path.exists():
            logger.warning("Config %s not found; using defaults", path)
            return {}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.error("Failed to load config %s: %s", path, exc)
            return {}

    def _load_sources(self) -> List[Source]:
        path = self._sources_path
        if not path.exists():
            logger.warning("Sources file %s not found; using empty list", path)
            return []

        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.error("Failed to load sources %s: %s", path, exc)
            return []

        sources: List[Source] = []
        for cat, items in raw.items():
            if not isinstance(items, list):
                continue
            for item in items:
                if isinstance(item, dict) and item.get("enabled", True):
                    sources.append(
                        Source(
                            name=item.get("name", "unknown"),
                            url=item.get("url", ""),
                            category=item.get("category", cat),
                            type=item.get("type", "onion"),
                            enabled=item.get("enabled", True),
                            clearweb_mirror=item.get("clearweb_mirror"),
                        )
                    )
        return sources

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def set_keywords(self, keywords: List[str]) -> None:
        self._keywords = keywords

    def run_scan(self, depth: int = 2) -> ScanReport:
        """Execute a single scan cycle against all configured sources.

        Parameters
        ----------
        depth : int
            Crawl depth per source.

        Returns
        -------
        ScanReport
        """
        report = ScanReport()
        report.total_sources = len(self._sources)

        matcher = KeywordMatcher(
            keywords=self._keywords,
            case_sensitive=self._config.get("matching", {}).get("case_sensitive", False),
            fuzzy_threshold=self._config.get("matching", {}).get("fuzzy_threshold", 0.75),
            enable_exact=self._config.get("matching", {}).get("enable_exact", True),
            enable_regex=self._config.get("matching", {}).get("enable_regex", True),
            enable_fuzzy=self._config.get("matching", {}).get("enable_fuzzy", True),
        )

        # Check Tor connectivity
        tor_ip = self._tor_mgr.get_tor_ip()
        logger.info("Tor IP: %s — starting scan of %d sources", tor_ip, len(self._sources))

        sources = [s for s in self._sources if s.enabled]
        if not sources:
            logger.warning("No enabled sources to scan")
            self._db.close()
            return report
        with ThreadPoolExecutor(max_workers=min(8, len(sources))) as executor:
            future_map = {
                executor.submit(self._process_source, src, depth, matcher): src
                for src in sources
            }
            for future in as_completed(future_map):
                src = future_map[future]
                try:
                    result = future.result()
                    if result:
                        src_result, findings = result
                        report.findings.extend(findings)
                        if src_result.error:
                            report.sources_failed += 1
                        else:
                            report.sources_ok += 1
                        report.pages_crawled += 1  # simplified
                except Exception as exc:
                    logger.error("Source %s failed with exception: %s", src.name, exc)
                    report.sources_failed += 1

        # Deduplicate and store
        new_count = self._db.store_findings_batch(report.findings)
        report.new_findings = new_count

        # Enrichment
        self._run_enrichment(report)

        # Alert on new critical/high findings
        if new_count > 0:
            new_alerts = [f for f in report.findings
                          if f.severity in (Severity.CRITICAL, Severity.HIGH)]
            if new_alerts:
                self._alerts.send_batch_alert(new_alerts)

        self._db.close()
        logger.info(
            "Scan complete — %d sources, %d pages, %d findings (%d new)",
            report.total_sources,
            report.pages_crawled,
            len(report.findings),
            report.new_findings,
        )
        return report

    def _process_source(
        self, source: Source, depth: int, matcher: KeywordMatcher
    ) -> Optional[Tuple[CrawlResult, List[Finding]]]:
        """Crawl a single source and extract findings.

        Returns (crawl_result, findings_list) or None on complete failure.
        """
        logger.info("Crawling %s (%s)", source.name, source.url)
        try:
            result = self._engine.crawl(source, depth=depth)
        except Exception as exc:
            logger.error("Crawl error for %s: %s", source.url, exc)
            return None

        findings: List[Finding] = []
        if not result.raw_text or len(result.raw_text.strip()) < 20:
            self._db.log_crawl(
                source.url, "failed", error="empty_response" if not result.error else result.error
            )
            return (result, findings)

        # Pattern extraction
        extracted = self._extractor.extract_all(result.raw_text)

        # Keyword matching
        # Use chunks for more granular matching
        chunks = self._chunk_text(result.raw_text, 2048)
        seen_snippets: Set[str] = set()

        for chunk in chunks:
            matches = matcher.score(result.raw_text, chunk)
            for keyword, match_type, confidence in matches:
                snippet = chunk[:500]
                snippet_key = hashlib.md5(snippet.encode()).hexdigest()
                if snippet_key in seen_snippets:
                    continue
                seen_snippets.add(snippet_key)

                # Determine severity
                severity = self._determine_severity(
                    keyword, match_type, confidence, extracted
                )

                finding = Finding(
                    source_url=source.url,
                    snippet=snippet,
                    keyword=keyword,
                    match_type=match_type,
                    confidence=confidence,
                    severity=severity,
                    tags=[source.category, source.type, match_type.name.lower()],
                    extracted_emails=extracted.get("emails", []),
                    extracted_domains=extracted.get("domains", []),
                    extracted_credentials=extracted.get("credentials", []),
                    extracted_hashes=extracted.get("hashes", []),
                    extracted_crypto=extracted.get("crypto", []),
                )

                # Attach enrichment metadata as tags
                if extracted.get("credentials"):
                    finding.severity = Severity.CRITICAL
                    finding.tags.append("credential_leak")
                if match_type == MatchType.FUZZY and confidence < 0.85:
                    finding.tags.append("low_confidence")
                if source.category == "ransomware":
                    finding.tags.append("ransomware_blog")

                findings.append(finding)

        self._db.log_crawl(
            source.url,
            "ok" if not result.error else "partial",
            pages_count=1,
            findings_count=len(findings),
            error=result.error,
        )
        return (result, findings)

    @staticmethod
    def _chunk_text(text: str, chunk_size: int = 2048) -> List[str]:
        """Split text into overlapping chunks for granular matching."""
        if len(text) <= chunk_size:
            return [text]
        chunks: List[str] = []
        overlap = chunk_size // 4
        start = 0
        while start < len(text):
            end = start + chunk_size
            chunks.append(text[start:end])
            start += chunk_size - overlap
        return chunks

    @staticmethod
    def _determine_severity(
        keyword: str,
        match_type: MatchType,
        confidence: float,
        extracted: Dict[str, List[str]],
    ) -> Severity:
        """Heuristic to assign severity."""
        if extracted.get("credentials"):
            return Severity.CRITICAL
        if match_type == MatchType.EXACT and confidence >= 0.95:
            return Severity.HIGH
        if match_type == MatchType.REGEX:
            return Severity.HIGH
        if confidence >= 0.9:
            return Severity.MEDIUM
        return Severity.LOW

    def _run_enrichment(self, report: ScanReport) -> None:
        """Run WHOIS/OTX enrichment on extracted indicators."""
        if not (self._enrichment._do_whois or self._enrichment._otx_client):
            return

        all_domains: Set[str] = set()
        all_ips: Set[str] = set()
        all_hashes: Set[str] = set()

        for f in report.findings:
            all_domains.update(f.extracted_domains)
            all_hashes.update(f.extracted_hashes)
            all_ips.update(self._extractor.extract_ips(f.snippet))

        logger.info(
            "Enriching %d domains, %d IPs, %d hashes …",
            len(all_domains),
            len(all_ips),
            len(all_hashes),
        )

        # WHOIS
        if self._enrichment._do_whois:
            whois_data = self._enrichment.enrich_domains(list(all_domains))
            recent_domains = [
                d for d, info in whois_data.items()
                if info.get("is_recent")
            ]
            if recent_domains:
                logger.info(
                    "Flagged %d recently registered domains: %s",
                    len(recent_domains),
                    ", ".join(recent_domains[:10]),
                )
                # Tag findings with recent domains
                for f in report.findings:
                    for d in f.extracted_domains:
                        if d in recent_domains:
                            f.tags.append("recent_domain")
                            sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
                            if sev_order.get(f.severity.value, 5) > sev_order.get("high", 1):
                                f.severity = Severity.HIGH

        # OTX
        if self._enrichment._otx_client:
            otx_data = self._enrichment.enrich_indicators(
                list(all_ips), list(all_domains), list(all_hashes)
            )
            for f in report.findings:
                # Tag if any indicator has OTX pulses
                for ind in list(all_ips) + list(all_domains) + list(all_hashes):
                    if ind in otx_data and otx_data[ind]:
                        f.tags.append("otx_verified")
                        break

    # ------------------------------------------------------------------
    # Daemon mode
    # ------------------------------------------------------------------
    def run_daemon(
        self,
        interval: int = DEFAULT_INTERVAL,
        depth: int = DEFAULT_DEPTH,
        output_path: Optional[str] = None,
    ) -> None:
        """Continuously run scans on a configurable interval.

        Parameters
        ----------
        interval : int
            Seconds between scan cycles.
        depth : int
            Crawl depth per source.
        output_path : str or None
            Path for HTML/JSON reports per cycle.
        """
        logger.info(
            "Starting daemon — interval=%ds, depth=%d, keywords=%s",
            interval,
            depth,
            self._keywords,
        )

        def shutdown(signum: Any, frame: Any) -> None:
            logger.info("Received signal %s — shutting down gracefully …", signum)
            self._running.clear()

        signal.signal(signal.SIGINT, shutdown)
        signal.signal(signal.SIGTERM, shutdown)

        cycle = 0
        while self._running.is_set():
            cycle += 1
            logger.info("=== Scan cycle %d ===", cycle)
            start = time.perf_counter()

            try:
                report = self.run_scan(depth=depth)

                if output_path:
                    self._save_report(report, output_path)

                if report.new_findings > 0:
                    logger.info(
                        "Cycle %d — %d new findings",
                        cycle,
                        report.new_findings,
                    )
                else:
                    logger.info("Cycle %d — no new findings", cycle)

            except Exception as exc:
                logger.error("Scan cycle %d failed: %s\n%s", cycle, exc, traceback.format_exc())

            elapsed = time.perf_counter() - start
            sleep_time = max(1, interval - int(elapsed))
            logger.info(
                "Cycle %d took %ds — next cycle in %ds",
                cycle,
                int(elapsed),
                sleep_time,
            )

            # Sleep in small increments so we can react to shutdown signals
            for _ in range(sleep_time):
                if not self._running.is_set():
                    break
                time.sleep(1)

        self.cleanup()
        logger.info("Daemon stopped cleanly after %d cycles", cycle)

    def _save_report(self, report: ScanReport, output_path: str) -> None:
        """Save scan report to JSON and optionally HTML."""
        output = Path(output_path)

        # JSON output
        json_data = {
            "scan_id": report.scan_id,
            "timestamp": report.timestamp.isoformat(),
            "total_sources": report.total_sources,
            "sources_ok": report.sources_ok,
            "sources_failed": report.sources_failed,
            "pages_crawled": report.pages_crawled,
            "new_findings": report.new_findings,
            "findings": [
                {
                    "source_url": f.source_url,
                    "snippet": f.snippet[:500],
                    "keyword": f.keyword,
                    "confidence": f.confidence,
                    "severity": f.severity.value if isinstance(f.severity, Severity) else f.severity,
                    "tags": f.tags,
                    "timestamp": f.timestamp.isoformat() if isinstance(f.timestamp, datetime) else str(f.timestamp),
                }
                for f in report.findings
            ],
        }
        output.write_text(
            json.dumps(json_data, indent=2, default=str), encoding="utf-8"
        )
        logger.info("JSON report saved to %s", output.resolve())

        # HTML report
        html_path = output.with_suffix(".html")
        self._report_gen.generate(report, html_path)

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------
    def cleanup(self) -> None:
        self._tor_mgr.close()
        self._db.close()
        logger.info("Cleanup complete")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse and return CLI arguments.

    Parameters
    ----------
    argv : list of str or None
        Command-line arguments (defaults to sys.argv[1:]).

    Returns
    -------
    argparse.Namespace
    """
    parser = argparse.ArgumentParser(
        prog="dark_intel",
        description="Dark Web Intelligence Gatherer — monitor .onion services "
                    "for leaks, credentials, and ransomware announcements.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python dark_intel.py --keywords \"acme.com,leak\" --depth 2 --output report.json\n"
            "  python dark_intel.py --keywords \"company,breach\" --daemon --interval 21600\n"
            "  python dark_intel.py --keywords \"credentials\" --depth 1 --output report.html\n"
        ),
    )

    parser.add_argument(
        "--keywords",
        type=str,
        required=True,
        help="Comma-separated target keywords to monitor",
    )
    parser.add_argument(
        "--depth",
        type=int,
        default=DEFAULT_DEPTH,
        help=f"Crawl depth per source (default: {DEFAULT_DEPTH})",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Path for JSON/HTML report output (e.g. report.json or report.html)",
    )
    parser.add_argument(
        "--daemon",
        action="store_true",
        default=False,
        help="Run in persistent daemon mode with configurable polling",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=DEFAULT_INTERVAL,
        help=f"Polling interval in seconds for daemon mode (default: {DEFAULT_INTERVAL})",
    )
    parser.add_argument(
        "--config",
        type=str,
        default="config.json",
        help="Path to configuration file (default: config.json)",
    )
    parser.add_argument(
        "--sources",
        type=str,
        default="sources.json",
        help="Path to sources file (default: sources.json)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="Enable debug-level logging",
    )

    return parser.parse_args(argv)


def setup_logging(level: str = "INFO", log_file: Optional[str] = None) -> None:
    """Configure root logger with console and optional file handler.

    Parameters
    ----------
    level : str
        Logging level name.
    log_file : str or None
        Optional log file path.
    """
    handlers: List[logging.Handler] = []
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    )
    handlers.append(console)

    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        )
        handlers.append(fh)

    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        handlers=handlers,
    )


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point.

    Parameters
    ----------
    argv : list of str or None
        Command-line arguments.

    Returns
    -------
    int
        Exit code (0 = success).
    """
    args = parse_args(argv)

    # Load config for logging defaults
    try:
        cfg = json.loads(Path(args.config).read_text(encoding="utf-8"))
    except Exception:
        cfg = {}

    log_cfg = cfg.get("logging", {})
    log_level = "DEBUG" if args.verbose else log_cfg.get("level", "INFO")
    log_file = log_cfg.get("file")
    setup_logging(log_level, log_file)

    # Check prerequisites
    if not _HAS_SOCKS:
        logger.error(
            "PySocks is required. Install it with: pip install pysocks"
        )
        return 1
    if not _HAS_BEAUTIFULSOUP:
        logger.warning(
            "BeautifulSoup4/lxml recommended for better HTML parsing. "
            "Falling back to regex."
        )
    if not _HAS_JINJA2:
        logger.warning(
            "Jinja2 not installed. HTML report generation disabled."
        )

    app = DarkIntelApp(
        config_path=args.config,
        sources_path=args.sources,
    )

    keywords = [kw.strip() for kw in args.keywords.split(",") if kw.strip()]
    if not keywords:
        logger.error("At least one keyword is required")
        return 1
    app.set_keywords(keywords)
    logger.info("Monitoring keywords: %s", keywords)

    try:
        if args.daemon:
            app.run_daemon(
                interval=args.interval,
                depth=args.depth,
                output_path=args.output,
            )
        else:
            report = app.run_scan(depth=args.depth)
            if args.output:
                app._save_report(report, args.output)
            else:
                # Print summary to console
                print(f"\n=== Scan Report: {report.scan_id} ===")
                print(f"  Timestamp:    {report.timestamp}")
                print(f"  Sources:      {report.sources_ok} ok / {report.sources_failed} failed")
                print(f"  Pages:        {report.pages_crawled}")
                print(f"  Total found:  {len(report.findings)}")
                print(f"  New stored:   {report.new_findings}")
                sev = defaultdict(int)
                for f in report.findings:
                    sev[f.severity.value] += 1
                for s in ("critical", "high", "medium", "low", "info"):
                    if sev[s]:
                        print(f"    {s}: {sev[s]}")
                print()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    finally:
        app.cleanup()

    return 0


if __name__ == "__main__":
    sys.exit(main())
