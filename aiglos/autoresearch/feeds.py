"""
aiglos/autoresearch/feeds.py

Ingest connectors for the Aiglos threat intelligence wiki.

Sources:
  - NVD CVE feed (NIST National Vulnerability Database)
  - GHSA (GitHub Security Advisories)
  - MITRE ATT&CK STIX bundle
  - Configurable RSS feeds for security blogs and incident reports

Each connector normalizes its source into the raw/ format the wiki expects:
a JSON file with a standard envelope, ready for wiki.py INGEST to process.

Usage:
    from aiglos.autoresearch.feeds import FeedManager

    fm = FeedManager(raw_dir="aiglos/autoresearch/raw")
    results = fm.fetch_all()
    for item in results.new_items:
        print(f"New: {item.slug} ({item.source_type})")
"""

from __future__ import annotations

import json
import time
import hashlib
import logging
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ── Raw item envelope ─────────────────────────────────────────────────────────

@dataclass
class RawItem:
    """
    Normalized raw intelligence item.
    Written to raw/{source_type}/{slug}.json by each connector.
    Read by wiki.py INGEST for synthesis into wiki pages.
    """
    slug:        str
    source_type: str          # cve | ghsa | mitre | blog | incident
    title:       str
    url:         str
    published:   str          # ISO 8601
    fetched:     str          # ISO 8601
    content:     str          # full text or structured JSON string
    tags:        list[str]    = field(default_factory=list)
    severity:    Optional[str] = None   # critical | high | medium | low | None
    cve_ids:     list[str]    = field(default_factory=list)
    cwe_ids:     list[str]    = field(default_factory=list)
    mitre_ids:   list[str]    = field(default_factory=list)
    raw_source:  dict         = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Return the raw item as a dictionary."""
        return {
            "slug":        self.slug,
            "source_type": self.source_type,
            "title":       self.title,
            "url":         self.url,
            "published":   self.published,
            "fetched":     self.fetched,
            "content":     self.content,
            "tags":        self.tags,
            "severity":    self.severity,
            "cve_ids":     self.cve_ids,
            "cwe_ids":     self.cwe_ids,
            "mitre_ids":   self.mitre_ids,
            "raw_source":  self.raw_source,
        }


@dataclass
class FetchResult:
    new_items:    list[RawItem] = field(default_factory=list)
    updated_items: list[RawItem] = field(default_factory=list)
    errors:       list[str]    = field(default_factory=list)
    sources_checked: int       = 0

    @property
    def total_new(self) -> int:
        """Return the count of newly fetched items."""
        return len(self.new_items)


# ── Utility ───────────────────────────────────────────────────────────────────

def _slug(text: str) -> str:
    """Normalize text to a filesystem-safe slug."""
    import re
    s = text.lower()
    s = re.sub(r'[^a-z0-9]+', '-', s)
    return s.strip('-')[:80]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _fetch_url(url: str, timeout: int = 30) -> Optional[str]:
    """Fetch URL content with basic error handling."""
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Aiglos-ThreatIntel/1.0 (security research)"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        logger.warning(f"Fetch failed for {url}: {e}")
        return None


def _severity_from_cvss(score: float) -> str:
    if score >= 9.0: return "critical"
    if score >= 7.0: return "high"
    if score >= 4.0: return "medium"
    return "low"


# ── NVD CVE Connector ─────────────────────────────────────────────────────────

class NVDConnector:
    """
    Fetches recent CVEs from the NIST National Vulnerability Database API.

    Filters for CVEs relevant to AI/ML agent attack surfaces:
    Python packages, LLM proxies, agent frameworks, MCP, and supply chain.
    """

    NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # Keywords that indicate AI/agent relevance
    RELEVANCE_KEYWORDS = [
        "llm", "large language model", "agent", "mcp", "model context",
        "langchain", "langgraph", "openai", "anthropic", "litellm",
        "ollama", "hugging face", "transformers", "pytorch", "tensorflow",
        "python", "pip", "pypi", "supply chain", "deserialization",
        "code execution", "prompt injection", "arbitrary code",
        "authentication bypass", "privilege escalation",
    ]

    def __init__(self, raw_dir: Path, days_back: int = 7, api_key: Optional[str] = None):
        self.raw_dir = raw_dir / "cves"
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.days_back = days_back
        self.api_key = api_key

    def fetch(self) -> list[RawItem]:
        """Fetch recent CVEs relevant to AI/agent attack surfaces."""
        from datetime import timedelta

        end = datetime.now(timezone.utc)
        start = end - timedelta(days=self.days_back)

        params = (
            f"?pubStartDate={start.strftime('%Y-%m-%dT%H:%M:%S.000')}"
            f"&pubEndDate={end.strftime('%Y-%m-%dT%H:%M:%S.000')}"
            f"&resultsPerPage=100"
        )
        url = self.NVD_API + params

        content = _fetch_url(url)
        if not content:
            return []

        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            logger.error(f"NVD JSON parse error: {e}")
            return []

        items = []
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            item = self._process_cve(cve)
            if item:
                items.append(item)

        logger.info(f"NVD: {len(items)} relevant CVEs from {len(data.get('vulnerabilities',[]))} total")
        return items

    def _process_cve(self, cve: dict) -> Optional[RawItem]:
        cve_id = cve.get("id", "")
        descriptions = cve.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

        # Filter for relevance
        desc_lower = desc.lower()
        if not any(kw in desc_lower for kw in self.RELEVANCE_KEYWORDS):
            return None

        # Extract severity
        metrics = cve.get("metrics", {})
        severity = None
        for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if metric_key in metrics and metrics[metric_key]:
                score = metrics[metric_key][0].get("cvssData", {}).get("baseScore", 0)
                severity = _severity_from_cvss(float(score))
                break

        # Extract CWEs
        cwe_ids = []
        for weakness in cve.get("weaknesses", []):
            for desc_item in weakness.get("description", []):
                val = desc_item.get("value", "")
                if val.startswith("CWE-"):
                    cwe_ids.append(val)

        # References
        refs = [r.get("url", "") for r in cve.get("references", [])[:5]]
        primary_url = refs[0] if refs else f"https://nvd.nist.gov/vuln/detail/{cve_id}"

        published = cve.get("published", _now())
        slug = _slug(cve_id)

        # Check if already fetched
        dest = self.raw_dir / f"{slug}.json"
        if dest.exists():
            return None

        item = RawItem(
            slug=slug,
            source_type="cve",
            title=f"{cve_id}: {desc[:100]}",
            url=primary_url,
            published=published,
            fetched=_now(),
            content=desc,
            tags=["cve", "nvd"] + (["critical"] if severity == "critical" else []),
            severity=severity,
            cve_ids=[cve_id],
            cwe_ids=cwe_ids,
            raw_source=cve,
        )

        dest.write_text(json.dumps(item.to_dict(), indent=2))
        return item


# ── GHSA Connector ────────────────────────────────────────────────────────────

class GHSAConnector:
    """
    Fetches GitHub Security Advisories via the GitHub Advisory Database API.

    Focuses on the Python ecosystem and AI/ML packages since these are
    the primary supply chain attack surface for agent deployments.
    """

    GHSA_API = "https://api.github.com/advisories"

    ECOSYSTEMS = ["pip", "npm"]  # Python and Node — primary agent surfaces

    def __init__(self, raw_dir: Path, days_back: int = 7,
                 github_token: Optional[str] = None):
        self.raw_dir = raw_dir / "ghsa"
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.days_back = days_back
        self.token = github_token

    def fetch(self) -> list[RawItem]:
        """Fetch recent GHSAs for Python and Node ecosystems."""
        items = []
        for ecosystem in self.ECOSYSTEMS:
            items.extend(self._fetch_ecosystem(ecosystem))
        return items

    def _fetch_ecosystem(self, ecosystem: str) -> list[RawItem]:
        from datetime import timedelta

        since = (datetime.now(timezone.utc) -
                 timedelta(days=self.days_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
        url = (f"{self.GHSA_API}?ecosystem={ecosystem}"
               f"&published={since}&per_page=50&severity=critical,high")

        headers = {"Accept": "application/vnd.github+json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
        except Exception as e:
            logger.warning(f"GHSA fetch failed for {ecosystem}: {e}")
            return []

        items = []
        for advisory in data if isinstance(data, list) else []:
            item = self._process_advisory(advisory)
            if item:
                items.append(item)

        logger.info(f"GHSA {ecosystem}: {len(items)} new advisories")
        return items

    def _process_advisory(self, adv: dict) -> Optional[RawItem]:
        ghsa_id = adv.get("ghsa_id", "")
        slug = _slug(ghsa_id)
        dest = self.raw_dir / f"{slug}.json"
        if dest.exists():
            return None

        severity_map = {
            "CRITICAL": "critical", "HIGH": "high",
            "MODERATE": "medium", "LOW": "low",
        }
        severity = severity_map.get(adv.get("severity", "").upper(), "medium")

        cve_ids = adv.get("cve_id", [])
        if isinstance(cve_ids, str):
            cve_ids = [cve_ids] if cve_ids else []

        # Build structured content
        packages = [
            f"{v.get('package', {}).get('name', 'unknown')} "
            f"({v.get('package', {}).get('ecosystem', '')})"
            for v in adv.get("vulnerabilities", [])
        ]
        content = (
            f"GHSA: {ghsa_id}\n"
            f"Summary: {adv.get('summary', '')}\n"
            f"Description: {adv.get('description', '')[:2000]}\n"
            f"Affected packages: {', '.join(packages)}\n"
            f"CVEs: {', '.join(cve_ids)}\n"
        )

        item = RawItem(
            slug=slug,
            source_type="ghsa",
            title=f"{ghsa_id}: {adv.get('summary', '')[:100]}",
            url=adv.get("html_url", f"https://github.com/advisories/{ghsa_id}"),
            published=adv.get("published_at", _now()),
            fetched=_now(),
            content=content,
            tags=["ghsa", "supply-chain", severity],
            severity=severity,
            cve_ids=cve_ids,
            raw_source=adv,
        )

        dest.write_text(json.dumps(item.to_dict(), indent=2))
        return item


# ── MITRE ATT&CK Connector ────────────────────────────────────────────────────

class MITREConnector:
    """
    Tracks MITRE ATT&CK updates relevant to AI/ML and agentic systems.

    Specifically monitors ATLAS (Adversarial Threat Landscape for
    Artificial-Intelligence Systems) for new technique additions.
    """

    ATLAS_URL = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/data/ATLAS.yaml"
    ATTCK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

    def __init__(self, raw_dir: Path):
        self.raw_dir = raw_dir / "mitre"
        self.raw_dir.mkdir(parents=True, exist_ok=True)

    def fetch(self) -> list[RawItem]:
        """Fetch latest MITRE ATLAS techniques."""
        items = []

        content = _fetch_url(self.ATLAS_URL)
        if not content:
            return []

        # Check if this version is new
        content_hash = hashlib.sha256(content.encode()).hexdigest()[:16]
        dest = self.raw_dir / f"atlas-{content_hash}.json"
        if dest.exists():
            return []  # Already processed this version

        # Parse YAML if available, otherwise store raw
        try:
            import yaml
            data = yaml.safe_load(content)
            techniques = data.get("techniques", [])
            for tech in techniques:
                tid = tech.get("id", "")
                name = tech.get("name", "")
                desc = tech.get("description", "")

                slug = f"atlas-{_slug(tid or name)}"
                item = RawItem(
                    slug=slug,
                    source_type="mitre",
                    title=f"ATLAS {tid}: {name}",
                    url=f"https://atlas.mitre.org/techniques/{tid}",
                    published=_now(),
                    fetched=_now(),
                    content=f"Technique: {tid}\nName: {name}\nDescription: {desc}",
                    tags=["mitre", "atlas", "technique"],
                    mitre_ids=[tid] if tid else [],
                    raw_source=tech,
                )
                item_dest = self.raw_dir / f"{slug}.json"
                if not item_dest.exists():
                    item_dest.write_text(json.dumps(item.to_dict(), indent=2))
                    items.append(item)

        except ImportError:
            # yaml not available — store raw content as single item
            item = RawItem(
                slug=f"atlas-{content_hash}",
                source_type="mitre",
                title=f"MITRE ATLAS Update {content_hash}",
                url=self.ATLAS_URL,
                published=_now(),
                fetched=_now(),
                content=content[:10000],
                tags=["mitre", "atlas"],
                raw_source={"hash": content_hash},
            )
            dest.write_text(json.dumps(item.to_dict(), indent=2))
            items.append(item)

        logger.info(f"MITRE: {len(items)} new techniques")
        return items


# ── RSS Security Blog Connector ───────────────────────────────────────────────

class RSSConnector:
    """
    Fetches security blog posts and incident reports via RSS/Atom feeds.

    Default feeds cover: Google Project Zero, Trail of Bits, NCC Group,
    SANS Internet Storm Center, Schneier on Security, Krebs on Security,
    The Hacker News, and AI security-specific sources.
    """

    DEFAULT_FEEDS = [
        # AI/agent security specific
        ("https://blog.trailofbits.com/feed/", "trail-of-bits", ["ai-security", "research"]),
        # General security with AI/supply chain relevance
        ("https://feeds.feedburner.com/TheHackersNews", "hacker-news", ["news", "breach"]),
        ("https://www.schneier.com/feed/atom/", "schneier", ["commentary", "analysis"]),
        ("https://krebsonsecurity.com/feed/", "krebs", ["incident", "breach"]),
        ("https://isc.sans.edu/rssfeed_full.xml", "sans-isc", ["threat-intel"]),
        # Google and Microsoft security blogs
        ("https://security.googleblog.com/feeds/posts/default", "google-security", ["research"]),
    ]

    def __init__(self, raw_dir: Path,
                 custom_feeds: Optional[list[tuple]] = None,
                 max_age_days: int = 7):
        self.raw_dir = raw_dir / "research"
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.feeds = custom_feeds or self.DEFAULT_FEEDS
        self.max_age_days = max_age_days

        # AI relevance keywords for filtering
        self.relevance_keywords = [
            "agent", "llm", "ai", "machine learning", "supply chain",
            "python", "injection", "backdoor", "malware", "exploit",
            "vulnerability", "zero-day", "rce", "arbitrary code",
            "authentication bypass", "privilege escalation", "memory",
            "prompt", "model", "inference", "api", "mcp",
        ]

    def fetch(self) -> list[RawItem]:
        """Fetch recent relevant posts from all configured feeds."""
        items = []
        for feed_url, source_name, default_tags in self.feeds:
            try:
                feed_items = self._fetch_feed(feed_url, source_name, default_tags)
                items.extend(feed_items)
                time.sleep(0.5)  # be polite
            except Exception as e:
                logger.warning(f"RSS fetch failed for {source_name}: {e}")

        logger.info(f"RSS: {len(items)} new relevant posts")
        return items

    def _fetch_feed(self, url: str, source_name: str,
                    default_tags: list[str]) -> list[RawItem]:
        content = _fetch_url(url)
        if not content:
            return []

        items = []
        try:
            root = ET.fromstring(content)
        except ET.ParseError:
            return []

        # Handle both RSS and Atom
        ns = {"atom": "http://www.w3.org/2005/Atom"}
        entries = (root.findall(".//item") or
                   root.findall(".//atom:entry", ns) or
                   root.findall(".//entry"))

        from datetime import timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(days=self.max_age_days)

        for entry in entries[:20]:  # cap per feed
            item = self._process_entry(entry, source_name, default_tags, cutoff, ns)
            if item:
                items.append(item)

        return items

    def _process_entry(self, entry, source_name: str, default_tags: list[str],
                       cutoff: datetime, ns: dict) -> Optional[RawItem]:
        # Extract fields from RSS or Atom format
        def get(tag: str, atom_tag: str = None) -> str:
            el = entry.find(tag)
            if el is None and atom_tag:
                el = entry.find(atom_tag, ns)
            return (el.text or "").strip() if el is not None else ""

        title = get("title", "atom:title")
        link  = get("link", "atom:link")
        if not link:
            link_el = entry.find("atom:link", ns)
            if link_el is not None:
                link = link_el.get("href", "")

        description = get("description", "atom:summary") or get("content", "atom:content")
        pub_date    = get("pubDate", "atom:published") or get("updated", "atom:updated")

        if not title or not link:
            return None

        # Check relevance
        combined = (title + " " + description).lower()
        if not any(kw in combined for kw in self.relevance_keywords):
            return None

        # Generate stable slug from URL
        url_hash = hashlib.sha256(link.encode()).hexdigest()[:12]
        slug = f"{source_name}-{url_hash}"
        dest = self.raw_dir / f"{slug}.json"
        if dest.exists():
            return None

        item = RawItem(
            slug=slug,
            source_type="blog",
            title=title[:200],
            url=link,
            published=pub_date or _now(),
            fetched=_now(),
            content=f"Title: {title}\n\nSummary: {description[:3000]}",
            tags=[source_name] + default_tags,
            raw_source={"source": source_name, "url": link},
        )

        dest.write_text(json.dumps(item.to_dict(), indent=2))
        return item


# ── Feed Manager ──────────────────────────────────────────────────────────────

class FeedManager:
    """
    Orchestrates all feed connectors.

    Usage:
        fm = FeedManager(raw_dir=Path("aiglos/autoresearch/raw"))
        result = fm.fetch_all()
        print(f"New items: {result.total_new}")
        for item in result.new_items:
            print(f"  {item.source_type}: {item.title[:60]}")
    """

    def __init__(
        self,
        raw_dir: str | Path,
        github_token:   Optional[str] = None,
        nvd_api_key:    Optional[str] = None,
        custom_feeds:   Optional[list] = None,
        days_back:      int = 7,
    ):
        self.raw_dir = Path(raw_dir)
        self.raw_dir.mkdir(parents=True, exist_ok=True)

        self.connectors = [
            NVDConnector(self.raw_dir, days_back=days_back, api_key=nvd_api_key),
            GHSAConnector(self.raw_dir, days_back=days_back, github_token=github_token),
            MITREConnector(self.raw_dir),
            RSSConnector(self.raw_dir, custom_feeds=custom_feeds,
                         max_age_days=days_back),
        ]

    def fetch_all(self) -> FetchResult:
        """Fetch from all connectors and return combined results."""
        result = FetchResult()

        for connector in self.connectors:
            try:
                items = connector.fetch()
                result.new_items.extend(items)
                result.sources_checked += 1
            except Exception as e:
                source = type(connector).__name__
                logger.error(f"{source} fetch error: {e}")
                result.errors.append(f"{source}: {e}")

        return result

    def fetch_single(self, source_type: str) -> FetchResult:
        """Fetch from a specific connector by source type."""
        type_map = {
            "cve":   NVDConnector,
            "ghsa":  GHSAConnector,
            "mitre": MITREConnector,
            "rss":   RSSConnector,
        }
        connector_class = type_map.get(source_type)
        if not connector_class:
            raise ValueError(f"Unknown source type: {source_type}. "
                             f"Valid: {list(type_map.keys())}")

        connector = next(
            (c for c in self.connectors if isinstance(c, connector_class)),
            None
        )
        if not connector:
            raise RuntimeError(f"No connector found for {source_type}")

        result = FetchResult()
        items = connector.fetch()
        result.new_items.extend(items)
        result.sources_checked = 1
        return result

    def list_raw(self, source_type: Optional[str] = None) -> list[Path]:
        """List all raw items, optionally filtered by source type."""
        if source_type:
            return sorted((self.raw_dir / source_type).glob("*.json"))
        return sorted(self.raw_dir.rglob("*.json"))

    def stats(self) -> dict:
        """Return counts of raw items by source type."""
        counts = {}
        for subdir in self.raw_dir.iterdir():
            if subdir.is_dir():
                counts[subdir.name] = len(list(subdir.glob("*.json")))
        return {
            "total": sum(counts.values()),
            "by_source": counts,
            "raw_dir": str(self.raw_dir),
        }
