#!/usr/bin/env python3
"""Ephemeral, high-verbosity observer for the P02 -> P06 decision flow.

The observer is deliberately detached from the application:

* it does not import application models or database clients;
* it does not create scan jobs, work items, evidence, logs, or artifacts;
* it never accepts an output-file option;
* tool stdout/stderr and all derived state stay in memory and are emitted only
  to stdout as JSON events;
* redirects and discovered URLs are restricted to the originally supplied
  host, so the diagnostic cannot silently expand scope.

For the strongest no-persistence guarantee, run it in a read-only ephemeral
container (the command is documented by ``--help`` and in the repository
README output printed at startup).
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import http.client
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


DEFAULT_PORTS = (
    21, 22, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995,
    1433, 1521, 2375, 3000, 3306, 3389, 5000, 5432, 5601, 5672,
    6379, 8000, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 9443,
)
TLS_PORTS = {443, 4443, 7443, 8443, 9443, 10443}
COMMON_PATHS = (
    "/", "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/api", "/api/", "/swagger", "/swagger.json", "/openapi.json",
    "/health", "/login", "/admin",
)
QUICK_PARAMETERS = (
    "id", "q", "query", "search", "page", "limit", "offset", "url",
    "redirect", "return", "next", "callback", "file", "path", "user",
)
TOOL_PATH = ":".join((
    "/opt/tools/bin",
    "/opt/tools/pipx/bin",
    "/opt/tools/pipx/venvs/arjun/bin",
    os.environ.get("PATH", ""),
))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def bounded(value: float) -> float:
    return round(max(0.0, min(100.0, float(value))), 2)


def percent(numerator: int | float, denominator: int | float) -> float:
    if not denominator:
        return 0.0
    return bounded((float(numerator) / float(denominator)) * 100.0)


def jaccard_percent(left: Iterable[Any], right: Iterable[Any]) -> float:
    a, b = set(left), set(right)
    if not a and not b:
        return 100.0
    union = a | b
    return percent(len(a & b), len(union))


def average(values: Iterable[float], default: float = 0.0) -> float:
    materialized = [float(value) for value in values]
    return bounded(sum(materialized) / len(materialized)) if materialized else bounded(default)


def weighted_score(parts: dict[str, float], weights: dict[str, float]) -> float:
    active = [(name, weight) for name, weight in weights.items() if name in parts and weight > 0]
    denominator = sum(weight for _, weight in active)
    if not denominator:
        return 0.0
    return bounded(sum(float(parts[name]) * weight for name, weight in active) / denominator)


def normalize_host(target: str) -> str:
    raw = str(target or "").strip()
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    host = str(parsed.hostname or "").strip().lower().rstrip(".")
    if not host or any(ch.isspace() for ch in host):
        raise ValueError("target must contain one valid hostname or IP")
    return host


def in_exact_scope(url: str, host: str) -> bool:
    try:
        return str(urlparse(url).hostname or "").lower().rstrip(".") == host
    except Exception:
        return False


def canonical_url(url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path or "/"
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), path, "", query, ""))


def safe_preview(value: str, limit: int = 1200) -> str:
    text = str(value or "")
    if len(text) <= limit:
        return text
    return f"{text[:limit]}… <truncated {len(text) - limit} chars>"


def parse_open_ports(text: str) -> set[int]:
    ports: set[int] = set()
    for match in re.finditer(r"(?m)(?<!\d)(\d{1,5})/(?:tcp|udp)\s+open\b", text, re.I):
        value = int(match.group(1))
        if 0 < value < 65536:
            ports.add(value)
    for match in re.finditer(
        r"(?m)(?:^|\s)(?:https?://)?((?:[a-z0-9_-]+\.)+[a-z0-9_-]+|\[[0-9a-f:]+\]):(\d{1,5})(?:\s|$)",
        text,
        re.I,
    ):
        value = int(match.group(2))
        if 0 < value < 65536:
            ports.add(value)
    return ports


def parse_urls(text: str, host: str) -> set[str]:
    urls: set[str] = set()
    for match in re.finditer(r"https?://[^\s\"'<>\]\[{}]+", str(text or ""), re.I):
        candidate = match.group(0).rstrip(".,);")
        if in_exact_scope(candidate, host):
            urls.add(canonical_url(candidate))
    return urls


def parameters_from_urls(urls: Iterable[str]) -> set[str]:
    return {
        key
        for url in urls
        for key, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)
        if key
    }


def classify_network(*, dns_ok: bool, canary_tcp_ok: bool, target_tcp_attempted: bool) -> dict[str, Any]:
    if dns_ok and not canary_tcp_ok:
        return {
            "category": "scanner_egress_failure",
            "reliable_negative": False,
            "coherence_percent": 0.0,
            "reason": "DNS resolves but an independent public TCP canary is unreachable.",
        }
    if not dns_ok and canary_tcp_ok:
        return {
            "category": "target_dns_failure",
            "reliable_negative": True,
            "coherence_percent": 90.0,
            "reason": "Scanner egress works, while the target did not resolve.",
        }
    if dns_ok and canary_tcp_ok and target_tcp_attempted:
        return {
            "category": "scanner_path_healthy",
            "reliable_negative": True,
            "coherence_percent": 100.0,
            "reason": "DNS and an independent public TCP canary both succeeded.",
        }
    return {
        "category": "network_inconclusive",
        "reliable_negative": False,
        "coherence_percent": 25.0,
        "reason": "There is not enough independent network evidence.",
    }


def classify_p02_scanner_semantics(
    *,
    naabu_status: str,
    naabu_ports: set[int],
    naabu_top_ports: int,
    nmap_status: str,
    nmap_ports: set[int],
    nmap_output: str,
) -> dict[str, Any]:
    """Separate process completion from trustworthy service evidence.

    WAF/CDN anycast edges may SYN/ACK hundreds of ports. Naabu reports those
    transport accepts faithfully, but they are not proof of hundreds of
    services. Nmap may also return zero after its own host-timeout; exit code 0
    still does not make that observation conclusive.
    """
    nmap_inconclusive = bool(
        re.search(
            r"skipping host .*host timeout|host seems down|0 hosts up",
            str(nmap_output or ""),
            re.I,
        )
    )
    nmap_service_rows = re.findall(
        r"(?m)^\d+/(?:tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?$",
        str(nmap_output or ""),
        re.I,
    )
    ambiguous_service_rows = [
        (service, detail)
        for service, detail in nmap_service_rows
        if service.lower().startswith("ssl/")
        and ("?" in service or "?" in str(detail or ""))
    ]
    nmap_edge_service_ambiguity = (
        len(nmap_service_rows) >= 5
        and percent(len(ambiguous_service_rows), len(nmap_service_rows)) >= 70.0
    )
    edge_threshold = max(50, int(max(1, naabu_top_ports) * 0.25))
    naabu_edge_accept_signature = len(naabu_ports) >= edge_threshold
    naabu_reliable = naabu_status == "completed" and not naabu_edge_accept_signature
    nmap_reliable = nmap_status == "completed" and not nmap_inconclusive

    if naabu_reliable and nmap_reliable:
        confirmed = naabu_ports & nmap_ports
        policy = "intersection_of_two_reliable_scanners"
    elif nmap_reliable:
        confirmed = set(nmap_ports)
        policy = "nmap_service_evidence"
    elif naabu_reliable:
        confirmed = set(naabu_ports)
        policy = "naabu_transport_evidence_single_source"
    else:
        confirmed = set()
        policy = "no_reliable_scanner_evidence"
    return {
        "naabu_edge_accept_signature": naabu_edge_accept_signature,
        "naabu_edge_threshold": edge_threshold,
        "naabu_reliable": naabu_reliable,
        "nmap_inconclusive": nmap_inconclusive,
        "nmap_reliable": nmap_reliable,
        "nmap_service_rows": len(nmap_service_rows),
        "nmap_ambiguous_service_rows": len(ambiguous_service_rows),
        "nmap_edge_service_ambiguity": nmap_edge_service_ambiguity,
        "service_identity_reliable": bool(nmap_reliable and not nmap_edge_service_ambiguity),
        "reliable_scanner_count": int(naabu_reliable) + int(nmap_reliable),
        "confirmation_policy": policy,
        "confirmed_ports": confirmed,
    }


@dataclass
class EventStream:
    verbose: int = 2
    started: float = field(default_factory=time.monotonic)
    sequence: int = 0
    events: list[dict[str, Any]] = field(default_factory=list)

    def emit(self, event: str, *, level: str = "INFO", detail: int = 1, **payload: Any) -> None:
        self.sequence += 1
        record = {
            "seq": self.sequence,
            "ts": utc_now(),
            "elapsed_ms": round((time.monotonic() - self.started) * 1000, 2),
            "level": level,
            "event": event,
            **payload,
        }
        self.events.append(record)
        if self.verbose >= detail:
            print(json.dumps(record, ensure_ascii=False, default=str), flush=True)


class NoRedirect:
    """Marker used by the raw HTTP probe: redirects are observed, never followed."""


def resolve_host(host: str, timeout: float) -> dict[str, Any]:
    started = time.monotonic()
    previous = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        rows = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        addresses = sorted({row[4][0] for row in rows})
        return {
            "status": "completed",
            "addresses": addresses,
            "duration_ms": round((time.monotonic() - started) * 1000, 2),
            "error": None,
        }
    except Exception as exc:
        return {
            "status": "failed",
            "addresses": [],
            "duration_ms": round((time.monotonic() - started) * 1000, 2),
            "error": f"{type(exc).__name__}: {exc}",
        }
    finally:
        socket.setdefaulttimeout(previous)


def tcp_connect(host: str, port: int, timeout: float) -> dict[str, Any]:
    started = time.monotonic()
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return {
                "port": int(port),
                "open": True,
                "duration_ms": round((time.monotonic() - started) * 1000, 2),
                "error": None,
            }
    except Exception as exc:
        return {
            "port": int(port),
            "open": False,
            "duration_ms": round((time.monotonic() - started) * 1000, 2),
            "error": type(exc).__name__,
        }


def scan_ports(host: str, ports: Iterable[int], timeout: float, workers: int) -> list[dict[str, Any]]:
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = [pool.submit(tcp_connect, host, int(port), timeout) for port in ports]
        return [future.result() for future in futures]


def raw_http_probe(url: str, timeout: float) -> dict[str, Any]:
    parsed = urlparse(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"
    headers = {
        "User-Agent": "EASM-P02-P06-Observer/1.0",
        "Accept": "*/*",
        "Connection": "close",
    }
    started = time.monotonic()
    connection: http.client.HTTPConnection | http.client.HTTPSConnection
    try:
        if parsed.scheme == "https":
            context = ssl.create_default_context()
            connection = http.client.HTTPSConnection(
                parsed.hostname,
                port,
                timeout=timeout,
                context=context,
            )
        else:
            connection = http.client.HTTPConnection(parsed.hostname, port, timeout=timeout)
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        body = response.read(262_144)
        response_headers = {key.lower(): value for key, value in response.getheaders()}
        return {
            "status": "completed",
            "url": url,
            "http_status": int(response.status),
            "reason": response.reason,
            "headers": response_headers,
            "body_bytes_observed": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "location": response_headers.get("location"),
            "server": response_headers.get("server"),
            "duration_ms": round((time.monotonic() - started) * 1000, 2),
            "error": None,
        }
    except Exception as exc:
        return {
            "status": "failed",
            "url": url,
            "http_status": None,
            "headers": {},
            "body_bytes_observed": 0,
            "body_sha256": None,
            "location": None,
            "server": None,
            "duration_ms": round((time.monotonic() - started) * 1000, 2),
            "error": f"{type(exc).__name__}: {exc}",
        }
    finally:
        try:
            connection.close()
        except Exception:
            pass


def tool_environment() -> dict[str, str]:
    env = dict(os.environ)
    env.update({
        # The documented runner mounts /root as tmpfs. Tools such as ffuf and
        # katana may initialize config there, but it exists only in RAM and
        # disappears with the ephemeral container.
        "HOME": "/root",
        "XDG_CACHE_HOME": "/root/.cache",
        "XDG_CONFIG_HOME": "/root/.config",
        "XDG_DATA_HOME": "/root/.local/share",
        "PYTHONDONTWRITEBYTECODE": "1",
        "NO_COLOR": "1",
        "PATH": TOOL_PATH,
    })
    return env


def run_command(
    stream: EventStream,
    *,
    phase: str,
    name: str,
    argv: list[str],
    timeout: float,
    stdin: str | None = None,
) -> dict[str, Any]:
    binary = shutil.which(argv[0], path=TOOL_PATH)
    safe_argv = [binary or argv[0], *argv[1:]]
    if not binary:
        result = {
            "phase": phase,
            "tool": name,
            "status": "unavailable",
            "argv": argv,
            "return_code": None,
            "duration_ms": 0.0,
            "stdout": "",
            "stderr": "",
            "error": f"binary_not_found:{argv[0]}",
        }
        stream.emit("tool_unavailable", level="WARNING", phase=phase, tool=name, argv=argv)
        return result

    stream.emit("tool_started", phase=phase, tool=name, argv=safe_argv, timeout_seconds=timeout)
    started = time.monotonic()
    try:
        completed = subprocess.run(
            safe_argv,
            input=stdin,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
            cwd="/",
            env=tool_environment(),
        )
        duration_ms = round((time.monotonic() - started) * 1000, 2)
        status = "completed" if completed.returncode == 0 else "failed"
        result = {
            "phase": phase,
            "tool": name,
            "status": status,
            "argv": safe_argv,
            "return_code": completed.returncode,
            "duration_ms": duration_ms,
            "stdout": completed.stdout or "",
            "stderr": completed.stderr or "",
            "error": None if status == "completed" else f"return_code:{completed.returncode}",
        }
    except subprocess.TimeoutExpired as exc:
        result = {
            "phase": phase,
            "tool": name,
            "status": "timeout",
            "argv": safe_argv,
            "return_code": None,
            "duration_ms": round((time.monotonic() - started) * 1000, 2),
            "stdout": (exc.stdout or "") if isinstance(exc.stdout, str) else "",
            "stderr": (exc.stderr or "") if isinstance(exc.stderr, str) else "",
            "error": f"timeout_after:{timeout}s",
        }
    except Exception as exc:
        result = {
            "phase": phase,
            "tool": name,
            "status": "failed",
            "argv": safe_argv,
            "return_code": None,
            "duration_ms": round((time.monotonic() - started) * 1000, 2),
            "stdout": "",
            "stderr": "",
            "error": f"{type(exc).__name__}: {exc}",
        }
    stream.emit(
        "tool_finished",
        level="INFO" if result["status"] == "completed" else "WARNING",
        phase=phase,
        tool=name,
        status=result["status"],
        return_code=result["return_code"],
        duration_ms=result["duration_ms"],
        stdout_bytes=len(result["stdout"]),
        stderr_bytes=len(result["stderr"]),
        stdout_preview=safe_preview(result["stdout"]),
        stderr_preview=safe_preview(result["stderr"]),
        error=result["error"],
    )
    return result


def command_completion_score(results: Iterable[dict[str, Any]]) -> float:
    rows = list(results)
    if not rows:
        return 0.0
    value = 0.0
    for row in rows:
        status = row.get("status")
        value += {
            "completed": 1.0,
            "unavailable": 0.25,
            "timeout": 0.15,
            "failed": 0.0,
        }.get(str(status), 0.0)
    return percent(value, len(rows))


def phase_result(
    phase: str,
    *,
    execution: float,
    coverage: float,
    agreement: float,
    evidence: float,
    observations: dict[str, Any],
) -> dict[str, Any]:
    dimensions = {
        "execution_percent": bounded(execution),
        "coverage_percent": bounded(coverage),
        "agreement_percent": bounded(agreement),
        "evidence_percent": bounded(evidence),
    }
    coherence = weighted_score(
        dimensions,
        {
            "execution_percent": 0.25,
            "coverage_percent": 0.25,
            "agreement_percent": 0.30,
            "evidence_percent": 0.20,
        },
    )
    return {
        "phase": phase,
        **dimensions,
        "coherence_percent": coherence,
        "reliable": coherence >= 70.0,
        "observations": observations,
    }


def origins_for(host: str, open_ports: set[int]) -> list[str]:
    origins: list[str] = []
    observed = set(open_ports)
    candidate_ports = (
        [443, 80]
        + sorted(observed & TLS_PORTS - {443})
        + sorted(observed - TLS_PORTS - {80})
    )
    candidate_ports = list(dict.fromkeys(candidate_ports))
    for port in candidate_ports:
        scheme = "https" if port in TLS_PORTS else "http"
        default = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
        origin = f"{scheme}://{host}" if default else f"{scheme}://{host}:{port}"
        origins.append(origin)
    return origins


def collapse_same_host_redirects(probes: list[dict[str, Any]], host: str) -> list[str]:
    """Keep HTTP for P06 comparison, but avoid duplicate P03-P05 work."""
    live = [
        str(probe["url"])
        for probe in probes
        if probe.get("status") == "completed" and probe.get("http_status") is not None
    ]
    redirected_origins: set[str] = set()
    for probe in probes:
        location = str(probe.get("location") or "")
        source = str(probe.get("url") or "")
        if (
            int(probe.get("http_status") or 0) in {301, 302, 307, 308}
            and location
            and in_exact_scope(location, host)
            and urlparse(source).scheme == "http"
            and urlparse(location).scheme == "https"
        ):
            redirected_origins.add(source)
    selected = [origin for origin in live if origin not in redirected_origins]
    return selected or live


def run_observer(args: argparse.Namespace) -> dict[str, Any]:
    stream = EventStream(verbose=args.verbose)
    host = normalize_host(args.target)
    state: dict[str, Any] = {
        "contract": {
            "name": "p02_p06_ephemeral_observer",
            "version": 2,
            "target": host,
            "scope_policy": "exact_host_only",
            "persistence": "memory_only_stdout_events",
            "database_access": False,
            "filesystem_output": False,
            "redirect_policy": "observe_but_do_not_follow",
        },
        "environment": {},
        "phases": {},
        "tool_runs": [],
    }
    stream.emit("observer_started", target=host, contract=state["contract"], argv=sys.argv)

    # Independent connectivity controls prevent an empty tool result from being
    # mistaken for a reliable "no ports / no HTTP" result.
    dns = resolve_host(host, args.connect_timeout)
    canary_dns = resolve_host(args.canary_host, args.connect_timeout)
    canary_tcp = tcp_connect(args.canary_host, args.canary_port, args.connect_timeout)
    network = classify_network(
        dns_ok=bool(dns["addresses"]),
        canary_tcp_ok=bool(canary_tcp["open"]),
        target_tcp_attempted=True,
    )
    state["environment"] = {
        "target_dns": dns,
        "canary_dns": canary_dns,
        "canary_tcp": canary_tcp,
        "classification": network,
    }
    stream.emit("network_preflight", **state["environment"])

    # P02: socket baseline + the same primary scanners used by the platform.
    stream.emit("phase_started", phase="P02", name="Port Service Discovery")
    socket_rows = scan_ports(host, args.ports, args.connect_timeout, args.socket_workers)
    socket_open = {row["port"] for row in socket_rows if row["open"]}
    for row in socket_rows:
        stream.emit("tcp_probe", detail=3, phase="P02", target=host, **row)

    naabu = run_command(
        stream,
        phase="P02",
        name="naabu",
        argv=["naabu", "-host", host, "-top-ports", str(args.naabu_top_ports), "-silent",
              "-rate", str(args.rate_limit), "-no-color"],
        timeout=args.phase_timeout,
    )
    nmap = run_command(
        stream,
        phase="P02",
        name="nmap",
        argv=["nmap", "-sV", "--version-light", "-Pn", "--open", "--top-ports",
              str(args.nmap_top_ports), "-T4", "--max-retries", "1",
              "--max-rtt-timeout", "2s", "--host-timeout",
              f"{int(args.phase_timeout)}s", host],
        timeout=args.phase_timeout + 10,
    )
    state["tool_runs"].extend([naabu, nmap])
    naabu_ports = parse_open_ports(naabu["stdout"])
    nmap_ports = parse_open_ports(nmap["stdout"])
    port_sets = {
        "socket": sorted(socket_open),
        "naabu": sorted(naabu_ports),
        "nmap": sorted(nmap_ports),
    }
    scanner_semantics = classify_p02_scanner_semantics(
        naabu_status=str(naabu["status"]),
        naabu_ports=naabu_ports,
        naabu_top_ports=args.naabu_top_ports,
        nmap_status=str(nmap["status"]),
        nmap_ports=nmap_ports,
        nmap_output=nmap["stdout"] + "\n" + nmap["stderr"],
    )
    completed_scanner_sets = []
    if scanner_semantics["naabu_reliable"]:
        completed_scanner_sets.append(naabu_ports)
    if scanner_semantics["nmap_reliable"]:
        completed_scanner_sets.append(nmap_ports)
    scanner_agreement = (
        jaccard_percent(completed_scanner_sets[0], completed_scanner_sets[1])
        if len(completed_scanner_sets) >= 2
        else (70.0 if len(completed_scanner_sets) == 1 else 0.0)
    )
    transport_agreement = average(
        [jaccard_percent(socket_open, ports) for ports in completed_scanner_sets],
        default=0.0,
    )
    port_agreement = weighted_score(
        {"scanner": scanner_agreement, "transport": transport_agreement},
        {"scanner": 0.75, "transport": 0.25},
    )
    # A TCP handshake is not service evidence on WAF/CDN anycast edges: some
    # providers accept many destination ports and close later. Only scanners
    # that complete protocol-aware probing can promote a port to P06.
    confirmed_ports = set(scanner_semantics["confirmed_ports"])
    scanner_completed = bool(scanner_semantics["reliable_scanner_count"])
    p02 = phase_result(
        "P02",
        execution=average([100.0, command_completion_score([naabu, nmap])]),
        coverage=percent(len(args.ports), len(DEFAULT_PORTS)),
        agreement=port_agreement,
        evidence=100.0 if network["reliable_negative"] else 0.0,
        observations={
            "resolved_addresses": dns["addresses"],
            "ports_by_probe": port_sets,
            "scanner_agreement_percent": scanner_agreement,
            "socket_vs_service_agreement_percent": transport_agreement,
            "scanner_semantics": {
                **scanner_semantics,
                "confirmed_ports": sorted(confirmed_ports),
            },
            "socket_connect_ports_auxiliary_only": sorted(socket_open),
            "tcp_accept_without_service_confirmation": sorted(socket_open - confirmed_ports),
            "confirmed_open_ports": sorted(confirmed_ports),
            "negative_result_reliable": bool(network["reliable_negative"] and scanner_completed),
        },
    )
    if network["category"] == "scanner_egress_failure":
        p02["coherence_percent"] = 0.0
        p02["reliable"] = False
    elif not scanner_completed:
        p02["coherence_percent"] = min(float(p02["coherence_percent"]), 55.0)
        p02["reliable"] = False
    elif scanner_semantics["nmap_edge_service_ambiguity"]:
        p02["coherence_percent"] = min(float(p02["coherence_percent"]), 69.0)
        p02["reliable"] = False
    state["phases"]["P02"] = p02
    stream.emit("phase_finished", **p02)

    # P06 eligibility is evaluated before discovery phases, mirroring the
    # platform's qualification gate. P03-P05 run only against live origins.
    all_candidate_origins = origins_for(host, confirmed_ports)
    candidate_origins = all_candidate_origins[: args.max_origins]
    raw_origin_probes = [raw_http_probe(origin, args.http_timeout) for origin in candidate_origins]
    for probe in raw_origin_probes:
        stream.emit("http_baseline_probe", detail=2, phase="P06", **probe)
    p06_live_origins = [
        probe["url"] for probe in raw_origin_probes
        if probe["status"] == "completed" and probe["http_status"] is not None
    ]
    live_origins = collapse_same_host_redirects(raw_origin_probes, host)
    stream.emit(
        "surface_origins_selected",
        phase="P03-P05",
        p06_live_origins=p06_live_origins,
        selected_surface_origins=live_origins,
        reason="same_host_http_to_https_redirects_are_not_retested",
    )

    # P03: bounded endpoint discovery. Every URL is rechecked against exact
    # host scope before it can influence later phases.
    stream.emit("phase_started", phase="P03", name="Endpoint Discovery", live_origins=live_origins)
    p03_tools: list[dict[str, Any]] = []
    endpoint_sources: dict[str, set[str]] = {"baseline": set()}
    for probe in raw_origin_probes:
        if probe["status"] == "completed":
            endpoint_sources["baseline"].add(canonical_url(probe["url"]))
    for origin in live_origins:
        ffuf = run_command(
            stream,
            phase="P03",
            name=f"ffuf:{origin}",
            argv=[
                "ffuf", "-u", f"{origin.rstrip('/')}/FUZZ",
                "-w", args.wordlist, "-mc", "200,204,301,302,307,401,403",
                "-ac", "-t", str(args.threads), "-rate", str(args.rate_limit),
                "-maxtime", str(int(args.discovery_timeout)), "-s", "-json",
            ],
            timeout=args.discovery_timeout + 10,
        )
        katana = run_command(
            stream,
            phase="P03",
            name=f"katana:{origin}",
            argv=["katana", "-u", origin, "-silent", "-d", "2", "-jc", "-kf", "all",
                  "-timeout", str(max(3, int(args.http_timeout)))],
            timeout=args.discovery_timeout,
        )
        p03_tools.extend([ffuf, katana])
        endpoint_sources[f"ffuf:{origin}"] = parse_urls(ffuf["stdout"], host)
        endpoint_sources[f"katana:{origin}"] = parse_urls(katana["stdout"], host)

    baseline_paths: set[str] = set()
    for origin in live_origins:
        for path in COMMON_PATHS:
            probe = raw_http_probe(f"{origin.rstrip('/')}{path}", args.http_timeout)
            if probe["status"] == "completed" and probe["http_status"] != 404:
                baseline_paths.add(canonical_url(probe["url"]))
            stream.emit("endpoint_probe", detail=3, phase="P03", **probe)
    endpoint_sources["common_paths"] = baseline_paths
    endpoints = set().union(*endpoint_sources.values()) if endpoint_sources else set()
    nonempty_sources = [values for values in endpoint_sources.values() if values]
    endpoint_agreement = (
        average(
            jaccard_percent(nonempty_sources[index], nonempty_sources[index + 1])
            for index in range(len(nonempty_sources) - 1)
        )
        if len(nonempty_sources) > 1 else (100.0 if nonempty_sources else 0.0)
    )
    p03 = phase_result(
        "P03",
        execution=command_completion_score(p03_tools) if p03_tools else (100.0 if not live_origins else 0.0),
        coverage=percent(len(live_origins), len(candidate_origins)),
        agreement=endpoint_agreement,
        evidence=100.0 if endpoints else (70.0 if not live_origins and p02["reliable"] else 20.0),
        observations={
            "eligible": bool(live_origins),
            "live_origins": live_origins,
            "endpoint_count": len(endpoints),
            "endpoints": sorted(endpoints)[: args.max_results],
            "source_counts": {key: len(value) for key, value in endpoint_sources.items()},
        },
    )
    state["phases"]["P03"] = p03
    stream.emit("phase_finished", **p03)

    # P04: Arjun plus parameters already observed in endpoint URLs and a small,
    # bounded differential probe set.
    stream.emit("phase_started", phase="P04", name="Parameter Discovery")
    p04_tools: list[dict[str, Any]] = []
    passive_parameters = parameters_from_urls(endpoints)
    arjun_text = ""
    for origin in live_origins:
        arjun = run_command(
            stream,
            phase="P04",
            name=f"arjun:{origin}",
            argv=[
                "arjun", "-u", origin, "-w", args.parameter_wordlist, "--stable",
                "-t", str(args.threads), "-T", str(max(2, int(args.http_timeout))),
                "-c", "20", "--rate-limit", str(args.rate_limit),
            ],
            timeout=args.discovery_timeout,
        )
        p04_tools.append(arjun)
        arjun_text += "\n" + arjun["stdout"] + "\n" + arjun["stderr"]
    arjun_parameters = {
        parameter for parameter in QUICK_PARAMETERS
        if re.search(rf"(?<![A-Za-z0-9_]){re.escape(parameter)}(?![A-Za-z0-9_])", arjun_text, re.I)
    }
    differential_parameters: set[str] = set()
    for origin in live_origins[:1]:
        baseline = raw_http_probe(origin, args.http_timeout)
        baseline_repeat = raw_http_probe(origin, args.http_timeout)
        baseline_stable = (
            baseline["status"] == "completed"
            and baseline_repeat["status"] == "completed"
            and baseline["http_status"] == baseline_repeat["http_status"]
            and baseline["body_sha256"] == baseline_repeat["body_sha256"]
        )
        for index, parameter in enumerate(QUICK_PARAMETERS[: args.max_parameter_probes]):
            separator = "&" if "?" in origin else "?"
            probe = raw_http_probe(
                f"{origin}{separator}{parameter}=easm-observer",
                args.http_timeout,
            )
            control = raw_http_probe(
                f"{origin}{separator}__easm_control_{index}=easm-observer",
                args.http_timeout,
            )
            changed = (
                baseline_stable
                and probe["status"] == "completed"
                and control["status"] == "completed"
                and baseline["status"] == "completed"
                and (
                    probe["http_status"] != baseline["http_status"]
                    or probe["body_sha256"] != baseline["body_sha256"]
                )
                and control["http_status"] == baseline["http_status"]
                and control["body_sha256"] == baseline["body_sha256"]
            )
            if changed:
                differential_parameters.add(parameter)
            stream.emit(
                "parameter_differential_probe",
                detail=3,
                phase="P04",
                parameter=parameter,
                changed=changed,
                baseline_stable=baseline_stable,
                baseline_status=baseline.get("http_status"),
                probe_status=probe.get("http_status"),
                control_status=control.get("http_status"),
                baseline_sha256=baseline.get("body_sha256"),
                probe_sha256=probe.get("body_sha256"),
                control_sha256=control.get("body_sha256"),
                error=probe.get("error"),
            )
    parameters = passive_parameters | arjun_parameters | differential_parameters
    p04_agreement = average([
        jaccard_percent(passive_parameters, arjun_parameters),
        jaccard_percent(arjun_parameters, differential_parameters),
        jaccard_percent(passive_parameters, differential_parameters),
    ])
    p04 = phase_result(
        "P04",
        execution=command_completion_score(p04_tools) if p04_tools else (100.0 if not live_origins else 0.0),
        coverage=percent(len(live_origins), len(live_origins)),
        agreement=p04_agreement,
        evidence=100.0 if parameters else (65.0 if live_origins else 30.0),
        observations={
            "passive_parameters": sorted(passive_parameters),
            "arjun_parameters": sorted(arjun_parameters),
            "differential_parameters": sorted(differential_parameters),
            "parameter_union": sorted(parameters),
        },
    )
    state["phases"]["P04"] = p04
    state["tool_runs"].extend(p03_tools + p04_tools)
    stream.emit("phase_finished", **p04)

    # P05: surface expansion and independent fingerprint/header/WAF views.
    stream.emit("phase_started", phase="P05", name="Surface Expansion")
    p05_tools: list[dict[str, Any]] = []
    p05_signals: dict[str, dict[str, Any]] = {}
    for origin in live_origins:
        commands = [
            ("whatweb", ["whatweb", "--no-errors", "-a", "3", "--colour=never",
                         "--follow-redirect=never", origin]),
            ("wafw00f", ["wafw00f", origin]),
            ("curl-headers", ["curl", "-k", "-sS", "-I", "--max-time",
                              str(int(args.http_timeout)), origin]),
        ]
        for tool, argv in commands:
            result = run_command(
                stream,
                phase="P05",
                name=f"{tool}:{origin}",
                argv=argv,
                timeout=args.discovery_timeout,
            )
            p05_tools.append(result)
            p05_signals[f"{tool}:{origin}"] = {
                "status": result["status"],
                "has_output": bool(result["stdout"].strip()),
                "output_bytes": len(result["stdout"]),
            }
    p05 = phase_result(
        "P05",
        execution=command_completion_score(p05_tools) if p05_tools else (100.0 if not live_origins else 0.0),
        coverage=percent(
            sum(1 for value in p05_signals.values() if value["has_output"]),
            len(p05_signals),
        ) if p05_signals else (100.0 if not live_origins else 0.0),
        agreement=percent(
            sum(1 for value in p05_signals.values() if value["status"] == "completed"),
            len(p05_signals),
        ) if p05_signals else 100.0,
        evidence=100.0 if any(value["has_output"] for value in p05_signals.values()) else 30.0,
        observations={"signals": p05_signals, "live_origins": live_origins},
    )
    state["phases"]["P05"] = p05
    state["tool_runs"].extend(p05_tools)
    stream.emit("phase_finished", **p05)

    # P06: compare the platform's primary httpx view with raw HTTP and curl.
    stream.emit("phase_started", phase="P06", name="HTTP Fingerprinting & WAF Detection")
    p06_tools: list[dict[str, Any]] = []
    httpx_live: set[str] = set()
    curl_live: set[str] = set()
    for origin in candidate_origins:
        httpx = run_command(
            stream,
            phase="P06",
            name=f"httpx:{origin}",
            argv=[
                "httpx", "-u", origin, "-silent", "-status-code", "-title",
                "-tech-detect", "-location", "-no-color", "-json",
                "-include-response-header", "-threads", str(args.threads),
                "-rate-limit", str(args.rate_limit),
            ],
            timeout=args.discovery_timeout,
        )
        curl = run_command(
            stream,
            phase="P06",
            name=f"curl:{origin}",
            argv=["curl", "-k", "-sS", "-I", "--max-time", str(int(args.http_timeout)), origin],
            timeout=args.http_timeout + 5,
        )
        p06_tools.extend([httpx, curl])
        if parse_urls(httpx["stdout"], host) or '"status_code":' in httpx["stdout"]:
            httpx_live.add(origin)
        if re.search(r"(?m)^HTTP/\S+\s+\d{3}", curl["stdout"]):
            curl_live.add(origin)
    raw_live = {
        probe["url"] for probe in raw_origin_probes
        if probe["status"] == "completed" and probe["http_status"] is not None
    }
    p06_agreement = average([
        jaccard_percent(raw_live, httpx_live),
        jaccard_percent(raw_live, curl_live),
        jaccard_percent(httpx_live, curl_live),
    ])
    p06 = phase_result(
        "P06",
        execution=average([
            command_completion_score(p06_tools),
            percent(sum(probe["status"] == "completed" for probe in raw_origin_probes), len(raw_origin_probes)),
        ]),
        coverage=percent(len(set(candidate_origins)), len(candidate_origins)),
        agreement=p06_agreement,
        evidence=100.0 if (raw_live or httpx_live or curl_live) else (
            75.0 if network["reliable_negative"] else 0.0
        ),
        observations={
            "candidate_origins": candidate_origins,
            "candidate_origins_before_limit": len(all_candidate_origins),
            "origin_limit": args.max_origins,
            "raw_http_live": sorted(raw_live),
            "httpx_live": sorted(httpx_live),
            "curl_live": sorted(curl_live),
            "qualified_live_origins": sorted(raw_live | httpx_live | curl_live),
            "negative_result_reliable": bool(network["reliable_negative"]),
        },
    )
    if network["category"] == "scanner_egress_failure":
        p06["coherence_percent"] = 0.0
        p06["reliable"] = False
    state["phases"]["P06"] = p06
    state["tool_runs"].extend(p06_tools)
    stream.emit("phase_finished", **p06)

    phase_scores = {phase: result["coherence_percent"] for phase, result in state["phases"].items()}
    global_coherence = weighted_score(
        phase_scores,
        {"P02": 0.30, "P03": 0.15, "P04": 0.15, "P05": 0.15, "P06": 0.25},
    )
    reliable = (
        global_coherence >= args.reliable_threshold
        and all(bool(result["reliable"]) for result in state["phases"].values())
        and network["category"] != "scanner_egress_failure"
    )
    final = {
        "contract": state["contract"],
        "started_at": stream.events[0]["ts"] if stream.events else utc_now(),
        "finished_at": utc_now(),
        "duration_ms": round((time.monotonic() - stream.started) * 1000, 2),
        "network": network,
        "phase_coherence_percent": phase_scores,
        "global_coherence_percent": global_coherence,
        "reliable_observation": reliable,
        "verdict": (
            "coherent_and_reliable"
            if reliable
            else "incoherent_or_insufficient_evidence"
        ),
        "counts": {
            "resolved_addresses": len(dns["addresses"]),
            "open_ports": len(confirmed_ports),
            "live_origins": len(raw_live | httpx_live | curl_live),
            "endpoints": len(endpoints),
            "parameters": len(parameters),
            "tool_runs": len(state["tool_runs"]),
            "events": len(stream.events) + 1,
        },
        "phases": state["phases"],
        "tool_run_summary": [
            {
                "phase": row["phase"],
                "tool": row["tool"],
                "status": row["status"],
                "return_code": row["return_code"],
                "duration_ms": row["duration_ms"],
                "stdout_bytes": len(row["stdout"]),
                "stderr_bytes": len(row["stderr"]),
                "error": row["error"],
            }
            for row in state["tool_runs"]
        ],
    }
    stream.emit("observer_finished", result=final)
    return final


def parse_ports_argument(value: str) -> tuple[int, ...]:
    ports: set[int] = set()
    for token in str(value or "").split(","):
        token = token.strip()
        if not token:
            continue
        port = int(token)
        if not 0 < port < 65536:
            raise argparse.ArgumentTypeError(f"invalid port: {port}")
        ports.add(port)
    if not ports:
        raise argparse.ArgumentTypeError("at least one port is required")
    return tuple(sorted(ports))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Observe P02-P06 in memory with verbose JSON events. No database, "
            "work-item, artifact, or output-file writes are performed."
        ),
        epilog=(
            "Strong isolation example: docker run --rm --read-only "
            "--tmpfs /tmp:rw,noexec,nosuid,size=64m --network easm_default "
            "--tmpfs /root:rw,exec,nosuid,size=64m "
            "--cap-add NET_RAW --cap-add NET_ADMIN "
            "-v easm_kali_tools:/opt/tools:ro "
            "-v \"$PWD/kali-runner/scripts/p02_p06_observer.py:"
            "/observer.py:ro\" "
            "-v \"$PWD/kali-runner/profiles:/app/profiles:ro\" "
            "--entrypoint python easm-kali_runner "
            "/observer.py valid.com -vvv"
        ),
    )
    parser.add_argument("target", help="One exact hostname or IP. Scope is never expanded.")
    parser.add_argument("-v", "--verbose", action="count", default=1, help="Repeat up to -vvv.")
    parser.add_argument("--ports", type=parse_ports_argument, default=DEFAULT_PORTS)
    parser.add_argument("--connect-timeout", type=float, default=3.0)
    parser.add_argument("--http-timeout", type=float, default=12.0)
    parser.add_argument("--phase-timeout", type=float, default=180.0)
    parser.add_argument("--discovery-timeout", type=float, default=60.0)
    parser.add_argument("--socket-workers", type=int, default=24)
    parser.add_argument("--threads", type=int, default=10)
    parser.add_argument("--rate-limit", type=int, default=30)
    parser.add_argument("--naabu-top-ports", type=int, default=1000)
    parser.add_argument("--nmap-top-ports", type=int, default=200)
    parser.add_argument("--max-origins", type=int, default=4)
    parser.add_argument("--max-results", type=int, default=250)
    parser.add_argument("--max-parameter-probes", type=int, default=10)
    parser.add_argument(
        "--wordlist",
        default="/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt",
    )
    parser.add_argument("--parameter-wordlist", default="/app/profiles/quick-params.txt")
    parser.add_argument("--canary-host", default="1.1.1.1")
    parser.add_argument("--canary-port", type=int, default=443)
    parser.add_argument("--reliable-threshold", type=float, default=70.0)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    args.verbose = min(3, max(0, int(args.verbose or 0)))
    try:
        result = run_observer(args)
    except KeyboardInterrupt:
        print(json.dumps({
            "ts": utc_now(),
            "level": "WARNING",
            "event": "observer_interrupted",
            "persistence": "memory_only_stdout_events",
        }), flush=True)
        return 130
    except Exception as exc:
        print(json.dumps({
            "ts": utc_now(),
            "level": "ERROR",
            "event": "observer_failed",
            "error": f"{type(exc).__name__}: {exc}",
            "persistence": "memory_only_stdout_events",
        }), flush=True)
        return 2
    return 0 if result["reliable_observation"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
