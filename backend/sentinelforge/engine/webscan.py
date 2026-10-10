"""Website security check: common, well-understood web misconfigurations, found with a handful of ordinary requests.

Deliberately passive and bounded:

- one site per scan, authorized and allow-listed like every other target (loopback is always allowed)
- only GET requests with normal paths; no payloads, no fuzzing, no logins, no form submission
- at most MAX_REQUESTS requests, a per-request timeout, response bodies capped, redirects only within the same host
- secrets found in exposed files are never stored: evidence keeps variable names, never values

It reports what it observes. A missing header is a weakness, not proof of an exploitable vulnerability. Library
versions are read from script and stylesheet URLs (or a version banner in a same-host file) and compared to
published fix versions. A match is not proof the site can be exploited. A clean result does not cover
authentication, business logic, or injection flaws (use an active scanner such as OWASP ZAP for those, on
systems you are authorized to test).
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import httpx
from pydantic import BaseModel, Field

from .. import PACK_VERSION, __version__
from ..adapters import ScopeError
from ..models import SEVERITY_RANK, CaseResult, Evidence, Finding, Run, Scope
from .libraries import (
    LIMITATION as LIBRARY_LIMITATION,
    MAX_LIBRARY_FILES,
    LibraryHit,
    inspect_html,
    is_affected,
    same_host_script,
    version_from_banner,
)

PACK = "web_security"
MAX_REQUESTS = 15
MAX_BODY_BYTES = 200_000
PROBE_ORIGIN = "https://sentinelforge-cors-probe.invalid"
LOOPBACK = {"localhost", "127.0.0.1", "::1"}
USER_AGENT = f"SentinelForge/{__version__} (+https://github.com/tuxlimr/sentinelforge; authorized security check)"

# Exposed files, each with a content signature so "200 for everything" sites do not cause false positives.
SENSITIVE_FILES = [
    ("WEB-020", "/.git/HEAD", re.compile(r"^ref: refs/", re.M), "critical", "Git repository exposed",
     "Source code and history (often including secrets) can be downloaded from the .git directory.",
     "Block access to /.git in the web server config, and never deploy the .git directory."),
    ("WEB-021", "/.env", re.compile(r"^[A-Z][A-Z0-9_]{2,}\s*=", re.M), "critical", "Environment file exposed",
     "The .env file usually holds database passwords, API keys and other secrets.",
     "Remove .env from the web root, block dotfiles in the web server, and rotate every secret it contained."),
    ("WEB-022", "/phpinfo.php", re.compile(r"<title>phpinfo\(\)</title>", re.I), "medium", "phpinfo() page exposed",
     "phpinfo() reveals server paths, configuration and module versions that help an attacker.",
     "Delete phpinfo.php from production servers."),
]


class WebScanRequest(BaseModel):
    url: str
    scope: Scope = Scope()
    timeout_seconds: float = Field(10, gt=0, le=60)
    label: str | None = None


@dataclass
class _Check:
    id: str
    name: str
    severity: str
    passed: bool
    observed: str = ""
    risk: str = ""
    expected: str = ""
    mitigation: str = ""
    sent: str = ""
    limitations: str = "Observed from a single request; behaviour may differ on other pages or for logged-in users."
    confidence: str = "high"
    evidence_quality: str = "deterministic"
    status: str = "confirmed"


@dataclass
class _Page:
    status_code: int
    headers: httpx.Headers
    text: str


@dataclass
class _Session:
    client: httpx.Client
    host: str
    used: int = 0
    notes: list[str] = field(default_factory=list)

    def get(self, url: str, headers: dict | None = None) -> _Page:
        """GET with the request budget and body cap enforced; redirects followed only on the same host."""
        for _ in range(4):
            if self.used >= MAX_REQUESTS:
                raise ScopeError(f"Request budget of {MAX_REQUESTS} reached.")
            self.used += 1
            with self.client.stream("GET", url, headers=headers) as response:
                body = bytearray()
                for chunk in response.iter_bytes():
                    body += chunk
                    if len(body) >= MAX_BODY_BYTES:
                        break
                page = _Page(response.status_code, response.headers,
                             bytes(body[:MAX_BODY_BYTES]).decode(response.encoding or "utf-8", "replace"))
                location = response.headers.get("location") if response.is_redirect else None
            if location is None:
                return page
            target = urljoin(url, location)
            if urlparse(target).hostname != self.host:
                self.notes.append(f"Redirect to another host ({urlparse(target).hostname}) was not followed.")
                return page
            url = target
        return page


def check_scope(request: WebScanRequest) -> str:
    parsed = urlparse(request.url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ScopeError("URL must be a full http(s) URL, e.g. https://your-site.example.com/")
    if parsed.username or parsed.password:
        raise ScopeError("Do not put credentials in the URL.")
    host = parsed.hostname
    if host.lower() not in LOOPBACK:
        if not request.scope.authorization_confirmed:
            raise ScopeError("Authorization must be explicitly confirmed to scan a non-local site.")
        if host not in request.scope.allowed_hosts:
            raise ScopeError(f"Host '{host}' is not listed in allowed hosts.")
    return host


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host.lower() == "localhost"


def _header_checks(response: _Page, https: bool) -> list[_Check]:
    h = response.headers
    csp = h.get("content-security-policy", "")
    checks = [
        _Check("WEB-001", "Content-Security-Policy header", "medium", bool(csp),
               observed=f"Content-Security-Policy: {csp}" if csp else "no Content-Security-Policy header",
               risk="Without a CSP, an injected script runs with the full privileges of the page (XSS impact is higher)",
               expected="A Content-Security-Policy header restricting script sources.",
               mitigation="Add a Content-Security-Policy header; start with default-src 'self' and tighten from there."),
        _Check("WEB-002", "Clickjacking protection", "medium",
               "frame-ancestors" in csp.lower() or h.get("x-frame-options", "").upper() in ("DENY", "SAMEORIGIN"),
               observed=f"X-Frame-Options: {h.get('x-frame-options', '(missing)')}; CSP frame-ancestors: {'yes' if 'frame-ancestors' in csp.lower() else 'no'}",
               risk="The site can be framed by another site and users tricked into clicking hidden buttons",
               expected="X-Frame-Options: DENY/SAMEORIGIN, or CSP frame-ancestors.",
               mitigation="Send Content-Security-Policy: frame-ancestors 'self' (or X-Frame-Options: DENY)."),
        _Check("WEB-003", "X-Content-Type-Options: nosniff", "low", h.get("x-content-type-options", "").lower() == "nosniff",
               observed=f"X-Content-Type-Options: {h.get('x-content-type-options', '(missing)')}",
               risk="Browsers may MIME-sniff responses and execute content as script",
               expected="X-Content-Type-Options: nosniff.", mitigation="Add the header X-Content-Type-Options: nosniff."),
        _Check("WEB-004", "Referrer-Policy header", "low", bool(h.get("referrer-policy")),
               observed=f"Referrer-Policy: {h.get('referrer-policy', '(missing)')}",
               risk="Full URLs (which may contain tokens or IDs) can leak to other sites through the Referer header",
               expected="A Referrer-Policy such as strict-origin-when-cross-origin.",
               mitigation="Add Referrer-Policy: strict-origin-when-cross-origin."),
    ]
    if https:
        hsts = h.get("strict-transport-security", "")
        checks.append(_Check("WEB-005", "Strict-Transport-Security (HSTS)", "medium", "max-age=" in hsts.lower(),
                             observed=f"Strict-Transport-Security: {hsts or '(missing)'}",
                             risk="Users can be downgraded to plain HTTP and have traffic intercepted",
                             expected="Strict-Transport-Security with a max-age.",
                             mitigation="Add Strict-Transport-Security: max-age=31536000; includeSubDomains."))
    disclosed = [f"{name}: {h[name]}" for name in ("server", "x-powered-by", "x-aspnet-version") if re.search(r"\d", h.get(name, ""))]
    checks.append(_Check("WEB-006", "Software version disclosure", "low", not disclosed,
                         observed="; ".join(disclosed) or "no version numbers in Server / X-Powered-By headers",
                         risk="Exact software versions let attackers look up known vulnerabilities for that version",
                         expected="Server and framework headers without version numbers.",
                         mitigation="Remove or genericise Server / X-Powered-By headers (e.g. server_tokens off in nginx)."))
    if "<title>index of /" in response.text[:5000].lower():
        checks.append(_Check("WEB-007", "Directory listing", "medium", False, observed="page title is 'Index of /...'",
                             risk="Directory listing exposes every file in the folder, including ones never linked",
                             expected="No automatic directory listings.",
                             mitigation="Disable directory listing (autoindex off in nginx, Options -Indexes in Apache)."))
    return checks


def _cookie_checks(response: _Page, https: bool) -> list[_Check]:
    weak = []
    for raw in response.headers.get_list("set-cookie"):
        name = raw.split("=", 1)[0].strip()
        attributes = {part.split("=", 1)[0].strip().lower() for part in raw.split(";")[1:]}
        missing = [flag for flag, ok in (("HttpOnly", "httponly" in attributes), ("SameSite", "samesite" in attributes),
                                         ("Secure", "secure" in attributes or not https)) if not ok]
        if missing:
            weak.append(f"{name} (missing {', '.join(missing)})")  # cookie name only; values are never stored
    if not response.headers.get_list("set-cookie"):
        return []
    return [_Check("WEB-008", "Cookie security flags", "medium", not weak,
                   observed="; ".join(weak) or "all cookies set Secure, HttpOnly and SameSite",
                   risk="Cookies without HttpOnly can be stolen by XSS, without Secure they travel over HTTP, "
                        "without SameSite they are sent on cross-site requests (CSRF)",
                   expected="Every cookie sets HttpOnly, SameSite and (on HTTPS) Secure.",
                   mitigation="Set HttpOnly; Secure; SameSite=Lax (or Strict) on session and auth cookies.")]


def _cors_check(session: _Session, url: str) -> _Check:
    response = session.get(url, headers={"Origin": PROBE_ORIGIN})
    allow = response.headers.get("access-control-allow-origin", "")
    credentials = response.headers.get("access-control-allow-credentials", "").lower() == "true"
    reflected = allow == PROBE_ORIGIN
    severity = "high" if reflected and credentials else "medium"
    return _Check("WEB-010", "CORS trusts arbitrary origins", severity, not reflected,
                  observed=f"Origin: {PROBE_ORIGIN} -> Access-Control-Allow-Origin: {allow or '(none)'}, "
                           f"Allow-Credentials: {str(credentials).lower()}",
                  sent=f"GET {url} with Origin: {PROBE_ORIGIN}",
                  risk="Any website can read this site's responses" + (" with the user's cookies" if credentials else ""),
                  expected="Access-Control-Allow-Origin only for an explicit list of trusted origins.",
                  mitigation="Replace origin reflection with an allowlist of trusted origins; never combine it with credentials.")


def _file_checks(session: _Session, base: str) -> list[_Check]:
    checks = []
    for check_id, path, signature, severity, title, risk, fix in SENSITIVE_FILES:
        url = urljoin(base, path)
        response = session.get(url)
        exposed = response.status_code == 200 and bool(signature.search(response.text))
        observed = f"HTTP {response.status_code} for {path}"
        if exposed and path == "/.env":  # never keep secret values: names only
            names = re.findall(r"^([A-Z][A-Z0-9_]{2,})\s*=", response.text, re.M)
            observed += f"; contains {len(names)} variables: {', '.join(names[:10])} (values not stored)"
        elif exposed:
            observed += "; content matches " + title.lower()
        checks.append(_Check(check_id, title, severity, not exposed, observed=observed, sent=f"GET {url}", risk=risk,
                             expected=f"{path} is not publicly accessible.", mitigation=fix,
                             limitations="Checks one well-known path; other copies or names are not covered."))
    return checks


def _short(value: str) -> str:
    value = " ".join(value.split())
    return value if len(value) <= 140 else value[:137] + "..."


def _library_checks(session: _Session, page_url: str, page: _Page) -> list[_Check]:
    """Compare library versions visible on the page with published fix versions. Same-host scripts only."""
    hits = inspect_html(page.text)
    enriched: list[LibraryHit] = []
    fetches = 0
    for hit in hits:
        if hit.version is not None:
            enriched.append(hit)
            continue
        if not hit.script_src:
            session.notes.append(f"{hit.rule.name} is referenced, but its version is not in the URL.")
            continue
        script_url = same_host_script(hit.script_src, page_url, session.host)
        if script_url is None:
            session.notes.append(f"{hit.rule.name} is referenced, but its version is not in the URL and the file is on another host.")
            continue
        if fetches >= MAX_LIBRARY_FILES:
            session.notes.append(f"Stopped after reading {MAX_LIBRARY_FILES} same-host script files for library versions.")
            continue
        try:
            script = session.get(script_url)
        except ScopeError:
            session.notes.append("Stopped reading script files: request budget reached.")
            break
        except httpx.HTTPError:
            session.notes.append(f"Could not read a same-host script to identify {hit.rule.name}.")
            continue
        fetches += 1
        version = version_from_banner(hit.rule, script.text)
        if version is None:
            session.notes.append(f"{hit.rule.name} is referenced at {_short(script_url)}, but no version banner was found.")
            continue
        enriched.append(LibraryHit(hit.rule, version, script_url))

    grouped: dict[str, list[LibraryHit]] = {}
    for hit in enriched:
        if hit.version is None or (hit.rule.case_id == "WEB-036" and hit.version[0] != 1):
            continue
        grouped.setdefault(hit.rule.case_id, []).append(hit)
    if not grouped:
        return [_Check("WEB-030", "Client libraries: none recognized", "low", True,
                        observed="No recognized library version in script or stylesheet URLs.",
                        limitations="Only looks at this page's script and stylesheet URLs, plus up to three same-host script banners. "
                                    "Bundled libraries without a version are not identified.")]

    checks = []
    for case_id, group in grouped.items():
        rule = group[0].rule
        affected = [hit for hit in group if is_affected(rule, hit.version)]  # type: ignore[arg-type]
        chosen = min(affected, key=lambda hit: hit.version or ()) if affected else max(group, key=lambda hit: hit.version or ())
        version = chosen.version
        assert version is not None
        version_text = ".".join(str(part) for part in version)
        others = sorted({".".join(str(part) for part in hit.version) for hit in group if hit.version != version})
        where = "; ".join(_short(hit.source) for hit in group[:3])
        observed = f"{rule.name} {version_text} referenced at {where}"
        if others:
            observed += f"; also saw {', '.join(others)}"
        vulnerable = bool(affected)
        label = f"{rule.name} {version_text}" + (" (known-vulnerable range)" if vulnerable else "")
        checks.append(_Check(
            case_id, label, rule.severity, not vulnerable,
            observed=observed, risk=rule.risk if vulnerable else "", expected=rule.expected,
            mitigation=rule.mitigation, sent=f"GET {page_url}",
            limitations=LIBRARY_LIMITATION, confidence="medium", evidence_quality="heuristic", status="confirmed",
        ))
    return checks


def _to_finding(check: _Check, url: str) -> Finding:
    return Finding(
        id=f"F-{check.id}", case_id=check.id, status=check.status, severity=check.severity, confidence=check.confidence,
        evidence_quality=check.evidence_quality, title=check.name, pack=PACK, category="Web security",
        risk=check.risk, expected=check.expected,
        evidence=Evidence(prompt=check.sent or f"GET {url}", response=check.observed, assertion=f"{check.name}: check failed"),
        reproductions="Observed from page markup. No exploit was attempted." if check.evidence_quality == "heuristic"
        else "Observed in a single request.",
        mitigation=check.mitigation, limitations=check.limitations,
    )


def scan(request: WebScanRequest) -> Run:
    host = check_scope(request)
    url = request.url
    https = url.startswith("https://")
    started = time.perf_counter()
    checks: list[_Check] = []
    warnings = [
        "Passive checks only: a missing header or an outdated library is not proof the site can be exploited.",
        "Library versions are read from this page's script and stylesheet URLs, or from a version banner in a same-host file.",
        "Not covered: authentication, access control, business logic, and injection flaws such as SQLi or XSS.",
    ]
    def session_for(verify: bool) -> _Session:
        client = httpx.Client(timeout=request.timeout_seconds, follow_redirects=False, verify=verify,
                              headers={"User-Agent": USER_AGENT})
        return _Session(client, host)

    session = session_for(verify=True)
    try:
        try:
            page = session.get(url)
        except httpx.ConnectError as error:
            if "CERTIFICATE_VERIFY_FAILED" not in str(error):
                raise ScopeError(f"Could not connect to {url}: {error}") from error
            checks.append(_Check("WEB-011", "Valid TLS certificate", "high", False, observed=f"TLS verification failed: {error}",
                                 risk="Browsers warn users away, and users trained to click through are open to interception",
                                 expected="A certificate valid for this hostname, issued by a trusted CA.",
                                 mitigation="Install a valid certificate (e.g. from Let's Encrypt) covering this hostname."))
            session.client.close()
            session = session_for(verify=False)  # still check everything else
            page = session.get(url)
        if not https and not _is_loopback(host):
            checks.append(_Check("WEB-012", "Served over HTTPS", "high", False, observed=f"{url} uses plain HTTP",
                                 risk="Everything, including passwords and cookies, travels unencrypted",
                                 expected="The site is served over HTTPS.",
                                 mitigation="Serve the site over HTTPS and redirect HTTP to HTTPS."))
        checks += _header_checks(page, https)
        checks += _cookie_checks(page, https)
        checks += _library_checks(session, url, page)
        checks.append(_cors_check(session, url))
        checks += _file_checks(session, url)
    except httpx.HTTPError as error:
        raise ScopeError(f"Could not reach {url}: {type(error).__name__}") from error
    finally:
        session.client.close()
    warnings += session.notes
    requests_made = session.used

    failed = [c for c in checks if c.passed is False]
    findings = sorted((_to_finding(c, url) for c in failed), key=lambda f: -SEVERITY_RANK[f.severity])
    results = [CaseResult(case_id=c.id, name=c.name, pack=PACK, category="Web security", severity=c.severity,
                          outcome="passed" if c.passed else "failed", duration_ms=0, note=c.observed[:200]) for c in checks]
    verdict = "fail" if any(SEVERITY_RANK[f.severity] >= SEVERITY_RANK["high"] for f in findings) else ("warn" if findings else "pass")
    now = datetime.now(timezone.utc)
    return Run(
        id=now.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:4], label=request.label, started_at=now.isoformat(timespec="seconds"),
        duration_ms=int((time.perf_counter() - started) * 1000), tool_version=__version__, pack_version=PACK_VERSION,
        config_hash=hashlib.sha256(url.encode()).hexdigest()[:12], target=url, target_kind="web", packs=[PACK],
        exit_status=1 if verdict == "fail" else 0, verdict=verdict,
        counts={"passed": sum(r.outcome == "passed" for r in results), "failed": len(failed), "error": 0, "skipped": 0},
        severity_counts={sev: sum(f.severity == sev for f in findings) for sev in SEVERITY_RANK},
        budget={"requests": requests_made, "cases_run": len(results), "max_cases": MAX_REQUESTS},
        results=results, findings=findings, skipped=[], warnings=warnings,
        sanitization="Cookie values and secret values from exposed files are never stored; only names are kept.",
    )
