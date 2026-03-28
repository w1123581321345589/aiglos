import re
import time
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse


class HttpVerdict(str, Enum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    BLOCK = "BLOCK"


@dataclass
class HttpScanResult:
    verdict: HttpVerdict
    rule_id: str
    rule_name: str
    reason: str
    url: str = ""
    method: str = ""
    allow_listed: bool = False
    latency_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)
    matched: str = ""

    def to_dict(self) -> dict:
        return {
            "type": "http_request",
            "verdict": self.verdict.value,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "reason": self.reason,
            "url": self.url,
            "method": self.method,
            "allow_listed": self.allow_listed,
            "latency_ms": round(self.latency_ms, 3),
        }


class AiglosBlockedRequest(RuntimeError):
    def __init__(self, result: HttpScanResult):
        self.result = result
        super().__init__(
            f"[Aiglos] HTTP blocked: {result.rule_id} {result.reason} url={result.url[:120]}"
        )


def _extract_host(url: str) -> str:
    """Pull the hostname out of a URL, stripping www prefix."""
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        return host.lstrip("www.")
    except Exception:
        return ""


def _host_is_allowed(host: str, allow_list: list[str]) -> bool:
    if not host or not allow_list:
        return False
    clean = host.lstrip("www.")
    for entry in allow_list:
        entry_clean = entry.lstrip("www.")
        if entry_clean.startswith("*."):
            suffix = entry_clean[1:]
            if clean.endswith(suffix) or clean == entry_clean[2:]:
                return True
        else:
            if clean == entry_clean:
                return True
    return False


# AWS IMDS, GCP metadata, loopback, RFC-1918, Alibaba IMDS, ULA IPv6
_SSRF_HOSTS = re.compile(
    r"^("
    r"169\.254\.169\.254"
    r"|metadata\.google\.internal"
    r"|localhost"
    r"|127\.0\.0\.1"
    r"|0\.0\.0\.0"
    r"|10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|100\.100\.100\.200"
    r"|fd[0-9a-f]{2}:.*"
    r")$",
    re.IGNORECASE,
)

_FINANCIAL_HOSTS = re.compile(
    r"("
    r"api\.stripe\.com"
    r"|api-m\.paypal\.com|api\.paypal\.com"
    r"|api\.squareup\.com|connect\.squareup\.com"
    r"|api\.braintreegateway\.com|payments\.braintree-api\.com"
    r"|checkout-test\.adyen\.com|checkout\.adyen\.com"
    r"|.*\.infura\.io"
    r"|.*\.alchemyapi\.io|.*\.alchemy\.com"
    r"|api\.coinbase\.com"
    r"|api\.binance\.com"
    r"|api\.kraken\.com"
    r"|api\.dwolla\.com"
    r"|.*\.plaid\.com"
    r")",
    re.IGNORECASE,
)

_ETH_SEND_PATTERN = re.compile(
    r"eth_send(Raw)?Transaction",
    re.IGNORECASE,
)

_RECON_HOSTS = re.compile(
    r"("
    r"api\.shodan\.io|shodan\.io"
    r"|haveibeenpwned\.com"
    r"|censys\.io"
    r"|zoomeye\.org"
    r")",
    re.IGNORECASE,
)

_SUPPLY_CHAIN_HOSTS = re.compile(
    r"("
    r"upload\.pypi\.org"
    r"|registry\.npmjs\.org"
    r"|rubygems\.org/api"
    r")",
    re.IGNORECASE,
)

_STAGING_DOMAINS = re.compile(
    r"("
    r".*\.ngrok\.io|.*\.ngrok\.app"
    r"|.*\.requestbin\.com|.*\.pipedream\.net"
    r"|.*\.webhook\.site"
    r"|.*\.burpcollaborator\.net"
    r")",
    re.IGNORECASE,
)

_CRED_BODY_PATTERNS = re.compile(
    r"("
    r"\.ssh/id_rsa|\.ssh/id_ed25519"
    r"|aws_secret|AKIA[A-Z0-9]{16}"
    r"|\.env\s|\.env\b"
    r"|sk-live-|sk_live_"
    r"|private.key|BEGIN RSA PRIVATE"
    r")",
    re.IGNORECASE,
)

_MODEL_EXFIL_PATTERNS = re.compile(
    r"("
    r"model_weights|\.safetensors|\.gguf|\.ggml"
    r"|checkpoint\.pt|model\.bin"
    r")",
    re.IGNORECASE,
)


def inspect_request(
    method: str,
    url: str,
    headers: dict | None = None,
    body=None,
    allow_list: list[str] | None = None,
    mode: str = "block",
) -> HttpScanResult:
    t0 = time.monotonic()
    headers = headers or {}
    allow_list = allow_list or []

    body_str = ""
    if body is not None:
        if isinstance(body, bytes):
            body_str = body.decode("utf-8", errors="replace")
        else:
            body_str = str(body)

    host = _extract_host(url)
    is_allowed = _host_is_allowed(host, allow_list)
    method_upper = method.upper()

    def _result(verdict, rule_id, rule_name, reason, matched=""):
        if mode == "audit":
            v = HttpVerdict.WARN
        elif verdict == HttpVerdict.BLOCK and mode == "warn" and rule_id != "T25":
            v = HttpVerdict.WARN
        else:
            v = verdict
        return HttpScanResult(
            verdict=v, rule_id=rule_id, rule_name=rule_name,
            reason=reason, url=url[:512], method=method_upper,
            allow_listed=is_allowed, latency_ms=(time.monotonic() - t0) * 1000,
            matched=matched,
        )

    if _SSRF_HOSTS.match(host):
        return _result(HttpVerdict.BLOCK, "T25", "SSRF",
                       f"SSRF target detected: {host}", host)

    if is_allowed:
        return _result(HttpVerdict.ALLOW, "none", "none", "")

    if method_upper != "GET" and _FINANCIAL_HOSTS.match(host):
        is_eth_node = bool(re.search(r"infura\.io|alchemyapi\.io|alchemy\.com", host, re.IGNORECASE))
        if is_eth_node:
            if body_str and _ETH_SEND_PATTERN.search(body_str):
                return _result(HttpVerdict.BLOCK, "T37", "FIN_EXEC",
                               "Ethereum send transaction detected", "eth_sendTransaction")
        else:
            return _result(HttpVerdict.BLOCK, "T37", "FIN_EXEC",
                           f"Financial transaction to {host}", host)

    if _RECON_HOSTS.match(host):
        return _result(HttpVerdict.BLOCK, "T22", "RECON",
                       f"Reconnaissance service: {host}", host)

    if _SUPPLY_CHAIN_HOSTS.match(host):
        return _result(HttpVerdict.BLOCK, "T36", "SUPPLY_CHAIN",
                       f"Package registry push: {host}", host)

    if _MODEL_EXFIL_PATTERNS.search(url) or _MODEL_EXFIL_PATTERNS.search(body_str):
        return _result(HttpVerdict.BLOCK, "T35", "MODEL_EXFIL",
                       "Model weights exfiltration detected")

    if body_str and _CRED_BODY_PATTERNS.search(body_str):
        if _STAGING_DOMAINS.match(host):
            return _result(HttpVerdict.BLOCK, "T19", "CRED_HARVEST",
                           f"Credential data sent to staging domain: {host}")
        return _result(HttpVerdict.BLOCK, "T19", "CRED_HARVEST",
                       "Credential content in request body")

    has_ssn = body_str and re.search(r"\b\d{3}-\d{2}-\d{4}\b", body_str)
    has_bulk_email = body_str and len(re.findall(r"[\w.+-]+@[\w-]+\.[\w.]+", body_str)) >= 3

    if _STAGING_DOMAINS.match(host):
        if has_ssn or has_bulk_email:
            return _result(HttpVerdict.BLOCK, "T20", "DATA_EXFIL",
                           f"Sensitive data sent to staging domain: {host}", host)
        return _result(HttpVerdict.WARN, "T20", "DATA_EXFIL",
                       f"Request to staging/exfil domain: {host}", host)

    if has_ssn:
        return _result(HttpVerdict.BLOCK, "T20", "DATA_EXFIL",
                       "Possible PII (SSN pattern) in body")

    if has_bulk_email:
        return _result(HttpVerdict.WARN, "T20", "DATA_EXFIL",
                       "Bulk email addresses in request body")

    return _result(HttpVerdict.ALLOW, "none", "none", "")


# TODO: per-session scoping — right now concurrent sessions share this list
_session_events: list = []


def get_session_http_events() -> list:
    return list(_session_events)


def clear_session_http_events() -> None:
    _session_events.clear()


def attach_http_intercept(mode="block", allow_list=None):
    """
    Monkeypatch requests, httpx, and aiohttp to route every outbound call
    through inspect_request before it hits the wire.

    Works by wrapping the low-level send/request method on each library.
    If the library is not installed, that adapter is silently skipped
    (zero required deps).
    """
    allow_list = allow_list or []
    patched = {}

    try:
        import requests as _requests

        _orig_send = _requests.Session.send

        def _aiglos_requests_send(self, prepared, **kw):
            result = inspect_request(
                method=prepared.method or "GET",
                url=prepared.url or "",
                headers=dict(prepared.headers or {}),
                body=prepared.body,
                allow_list=allow_list,
                mode=mode,
            )
            _session_events.append(result.to_dict())
            if result.verdict == HttpVerdict.BLOCK:
                raise AiglosBlockedRequest(result)
            return _orig_send(self, prepared, **kw)

        _requests.Session.send = _aiglos_requests_send
        patched["requests"] = True
    except ImportError:
        patched["requests"] = False

    try:
        import httpx as _httpx

        _orig_httpx_send = _httpx.Client.send

        def _aiglos_httpx_send(self, request, **kw):
            body = request.content if hasattr(request, "content") else None
            result = inspect_request(
                method=request.method,
                url=str(request.url),
                headers=dict(request.headers or {}),
                body=body,
                allow_list=allow_list,
                mode=mode,
            )
            _session_events.append(result.to_dict())
            if result.verdict == HttpVerdict.BLOCK:
                raise AiglosBlockedRequest(result)
            return _orig_httpx_send(self, request, **kw)

        _httpx.Client.send = _aiglos_httpx_send

        if hasattr(_httpx, "AsyncClient"):
            _orig_httpx_async = _httpx.AsyncClient.send

            async def _aiglos_httpx_async_send(self, request, **kw):
                body = request.content if hasattr(request, "content") else None
                result = inspect_request(
                    method=request.method,
                    url=str(request.url),
                    headers=dict(request.headers or {}),
                    body=body,
                    allow_list=allow_list,
                    mode=mode,
                )
                _session_events.append(result.to_dict())
                if result.verdict == HttpVerdict.BLOCK:
                    raise AiglosBlockedRequest(result)
                return await _orig_httpx_async(self, request, **kw)

            _httpx.AsyncClient.send = _aiglos_httpx_async_send

        patched["httpx"] = True
    except ImportError:
        patched["httpx"] = False

    try:
        import aiohttp as _aiohttp

        _orig_aiohttp_request = _aiohttp.ClientSession._request

        async def _aiglos_aiohttp_request(self, method, url, **kw):
            body = kw.get("data") or kw.get("json")
            result = inspect_request(
                method=method,
                url=str(url),
                headers=dict(kw.get("headers") or {}),
                body=body,
                allow_list=allow_list,
                mode=mode,
            )
            _session_events.append(result.to_dict())
            if result.verdict == HttpVerdict.BLOCK:
                raise AiglosBlockedRequest(result)
            return await _orig_aiohttp_request(self, method, url, **kw)

        _aiohttp.ClientSession._request = _aiglos_aiohttp_request
        patched["aiohttp"] = True
    except ImportError:
        patched["aiohttp"] = False

    return patched


def http_intercept_status() -> dict:
    return {"active": True, "events": len(_session_events)}
