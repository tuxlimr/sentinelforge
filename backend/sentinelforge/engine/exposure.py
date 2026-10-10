"""Network exposure check: which TCP ports on an application's host are open that should not be?

AI stacks often ship a vector database, cache, model server or notebook next to the app, listening on a
well-known port. This runs nmap as a plain TCP connect scan and flags open ports that are not on the caller's
expected list. It is deliberately narrow:

- one host per scan (no ranges, no CIDR), authorized and allow-listed like the HTTP target; loopback is always allowed
- nmap arguments are fixed: no NSE scripts, no service/OS detection, no user-supplied flags, no shell
- a bounded port list and a hard timeout

An open port is evidence of reachability only. It does not show the service is unauthenticated or exploitable.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import shutil
import subprocess
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from pydantic import BaseModel, Field

from .. import PACK_VERSION, __version__
from ..adapters import ScopeError
from ..models import SEVERITY_RANK, CaseResult, Evidence, Finding, Run, Scope

LOOPBACK = {"localhost", "127.0.0.1", "::1"}
MAX_PORTS = 100
MAX_XML_BYTES = 2_000_000
HOSTNAME = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")

# Ports where an unexpected listener is a data or control-plane exposure, not just an extra web server.
SENSITIVE_PORTS: dict[int, str] = {
    3306: "MySQL", 5432: "PostgreSQL", 6333: "Qdrant vector DB", 6379: "Redis", 8888: "Jupyter",
    9200: "Elasticsearch", 11434: "Ollama model server", 19530: "Milvus vector DB", 27017: "MongoDB",
}
# Common ports for an app plus its AI-stack companions.
DEFAULT_PORTS = [21, 22, 23, 80, 443, 3000, 3306, 5000, 5432, 6333, 6379, 7860, 8000, 8080, 8501, 8888, 9000, 9200,
                 11434, 19530, 27017]


class ExposureError(Exception):
    """nmap is missing, failed, or returned something unusable."""


class ExposureRequest(BaseModel):
    host: str
    expected_ports: list[int] = []
    ports: list[int] = Field(default_factory=lambda: list(DEFAULT_PORTS))
    scope: Scope = Scope()
    timeout_seconds: float = Field(60, gt=0, le=300)
    label: str | None = None


def find_nmap() -> str:
    path = shutil.which("nmap")
    if not path and os.name == "nt":
        for root in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)")):
            candidate = os.path.join(root or "", "Nmap", "nmap.exe")
            if root and os.path.isfile(candidate):
                path = candidate
    if not path:
        raise ExposureError("nmap was not found on PATH. Install it from https://nmap.org/download (Windows: `winget install Insecure.Nmap`).")
    return path


def check_scope(request: ExposureRequest) -> None:
    """Fail closed. A bare host only: nothing nmap could read as a flag, range, or second target."""
    host = request.host
    try:
        ipaddress.ip_address(host)
    except ValueError:
        # Digits, dots and dashes that are not a valid IP are nmap range syntax (10.0.0.1-50), never a hostname.
        if not HOSTNAME.match(host) or re.fullmatch(r"[\d.\-]+", host):
            raise ScopeError("Host must be a single hostname or IP address (no ranges, CIDR, flags or spaces).") from None
    if host.lower() not in LOOPBACK:
        if not request.scope.authorization_confirmed:
            raise ScopeError("Authorization must be explicitly confirmed to scan a non-loopback host.")
        if host not in request.scope.allowed_hosts:
            raise ScopeError(f"Host '{host}' is not listed in allowed hosts.")
    ports = request.ports
    if not ports or len(set(ports)) > MAX_PORTS or any(not 1 <= p <= 65535 for p in [*ports, *request.expected_ports]):
        raise ScopeError(f"Ports must be 1-65535, at most {MAX_PORTS} of them.")


def build_command(nmap: str, request: ExposureRequest) -> list[str]:
    ports = ",".join(str(p) for p in sorted(set(request.ports)))
    # -sT connect scan (no raw sockets/root), -Pn skip host discovery, -n no DNS, --open only open ports.
    return [nmap, "-sT", "-Pn", "-n", "--open", "-T3", "--max-retries", "1", "-p", ports, "-oX", "-", request.host]


def parse_open_ports(xml_text: str) -> list[dict]:
    """Open TCP ports from nmap's XML. The output is treated as untrusted: size-capped, no entity expansion."""
    if len(xml_text) > MAX_XML_BYTES or "<!ENTITY" in xml_text:
        raise ExposureError("nmap output was unexpectedly large or contained entity declarations; refusing to parse it.")
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as error:
        raise ExposureError(f"Could not parse nmap output: {error}") from error
    found = []
    for port in root.iter("port"):
        state = port.find("state")
        if port.get("protocol") == "tcp" and state is not None and state.get("state") == "open":
            service = port.find("service")
            found.append({"port": int(port.get("portid", "0")), "service": service.get("name", "unknown") if service is not None else "unknown"})
    return sorted(found, key=lambda item: item["port"])


def _mitigation(port: int) -> str:
    if port in SENSITIVE_PORTS:
        return (f"Do not expose {SENSITIVE_PORTS[port]} beyond the application. Bind it to localhost or a private network, "
                "firewall the port, and require authentication.")
    return "Close the port or firewall it if the service is not meant to be reachable; otherwise add it to the expected ports."


def _finding(request: ExposureRequest, command: list[str], item: dict) -> Finding:
    port, label = item["port"], SENSITIVE_PORTS.get(item["port"])
    return Finding(
        id=f"F-SF-NX-{port}", case_id=f"SF-NX-{port}", status="confirmed",
        severity="high" if label else "medium", confidence="high", evidence_quality="deterministic",
        title=f"Unexpected open port {port}/tcp" + (f" ({label})" if label else ""),
        pack="network_exposure", category="Network exposure",
        risk="A service outside the expected set is reachable from the scanning position",
        expected=f"Only these ports are open on {request.host}: {sorted(request.expected_ports) or 'none'}.",
        evidence=Evidence(prompt=" ".join(command[1:]), response=f"{port}/tcp open {item['service']} (service name is nmap's guess from the port number)",
                          assertion=f"port {port}/tcp is open and not in the expected list"),
        reproductions="Observed in a single connect scan. Re-run to confirm it is stable.",
        mitigation=_mitigation(port),
        limitations="Shows the port accepts connections, not that the service is unauthenticated or exploitable. "
                    "Results depend on where the scan runs from; firewalls may hide ports elsewhere.",
    )


def scan(request: ExposureRequest) -> Run:
    check_scope(request)
    nmap = find_nmap()
    command = build_command(nmap, request)
    started = time.perf_counter()
    try:
        done = subprocess.run(command, capture_output=True, text=True, timeout=request.timeout_seconds, shell=False, check=False)
    except subprocess.TimeoutExpired as error:
        raise ExposureError(f"nmap did not finish within {request.timeout_seconds:g}s.") from error
    if done.returncode != 0:
        raise ExposureError(f"nmap exited with status {done.returncode}: {done.stderr.strip()[:300]}")
    open_ports = parse_open_ports(done.stdout)

    expected = set(request.expected_ports)
    findings = [_finding(request, command, item) for item in open_ports if item["port"] not in expected]
    findings.sort(key=lambda f: -SEVERITY_RANK[f.severity])
    results = [
        CaseResult(case_id=f"SF-NX-{item['port']}", name=f"Port {item['port']}/tcp ({item['service']})", pack="network_exposure",
                   category="Network exposure", severity="high" if item["port"] in SENSITIVE_PORTS else "medium",
                   outcome="passed" if item["port"] in expected else "failed", duration_ms=0,
                   note="expected" if item["port"] in expected else "unexpected")
        for item in open_ports
    ]
    if not open_ports:
        results.append(CaseResult(case_id="SF-NX-000", name=f"No open ports among {len(set(request.ports))} probed", pack="network_exposure",
                                  category="Network exposure", severity="informational", outcome="passed", duration_ms=0))
    closed_expected = sorted(expected - {item["port"] for item in open_ports})
    warnings = [
        "An open port shows reachability only, not that the service is unauthenticated or exploitable.",
        f"Only {len(set(request.ports))} ports were probed from this scan position; a clean result does not cover other ports or networks.",
    ]
    if closed_expected:
        warnings.append(f"Expected ports not seen open: {closed_expected}. The app may be down or filtered.")

    now = datetime.now(timezone.utc)
    verdict = "fail" if any(SEVERITY_RANK[f.severity] >= SEVERITY_RANK["high"] for f in findings) else ("warn" if findings else "pass")
    config = request.model_dump_json(exclude={"scope"}) + request.host
    return Run(
        id=now.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:4], label=request.label, started_at=now.isoformat(timespec="seconds"),
        duration_ms=int((time.perf_counter() - started) * 1000), tool_version=__version__, pack_version=PACK_VERSION,
        config_hash=hashlib.sha256(config.encode()).hexdigest()[:12], target=request.host, target_kind="network",
        packs=["network_exposure"], exit_status=1 if verdict == "fail" else 0, verdict=verdict,
        counts={"passed": sum(r.outcome == "passed" for r in results), "failed": sum(r.outcome == "failed" for r in results), "error": 0, "skipped": 0},
        severity_counts={sev: sum(f.severity == sev for f in findings) for sev in SEVERITY_RANK},
        budget={"requests": len(set(request.ports)), "cases_run": len(results), "max_cases": MAX_PORTS},
        results=results, findings=findings, skipped=[], warnings=warnings,
        sanitization="No payloads or secrets are involved; evidence is the nmap command and the open-port line.",
    )
