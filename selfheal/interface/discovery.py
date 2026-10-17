"""Safe read-only host discovery for `selfheal init`."""

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import psutil

from selfheal.collectors.common import command
from selfheal.config import Config, Service

CRITICAL_KEYWORDS = ("db", "database", "postgres", "postgresql", "mysql", "mariadb", "redis", "etcd")
KNOWN_SYSTEMD_UNITS = ("nginx.service", "postgresql.service", "redis.service", "docker.service")


@dataclass
class DiscoverySummary:
    """Summary of read-only host scan performed during `selfheal init`."""

    services: list[Service] = field(default_factory=list)
    listening_ports: list[int] = field(default_factory=list)
    log_files: list[str] = field(default_factory=list)
    systemd_units: list[str] = field(default_factory=list)
    docker_containers: list[str] = field(default_factory=list)
    nginx_upstreams: dict[str, list[str]] = field(default_factory=dict)


def _safe_service_name(raw: str) -> str:
    """Normalize discovered identifiers to strict Service.name pattern."""
    cleaned = re.sub(r"[^A-Za-z0-9_.-]", "_", raw.strip())
    return cleaned[:128] or "service"


def _is_critical(name: str) -> bool:
    """Mark databases and stateful stores as CRITICAL (never auto-touched)."""
    lowered = name.lower()
    return any(k in lowered for k in CRITICAL_KEYWORDS)


def scan_listening_ports() -> list[int]:
    """Return sorted local listening TCP ports when OS permissions allow."""
    ports: set[int] = set()
    try:
        for conn in psutil.net_connections(kind="tcp"):
            if conn.status == psutil.CONN_LISTEN and conn.laddr and conn.laddr.port:
                ports.add(int(conn.laddr.port))
    except (psutil.Error, OSError):
        pass
    return sorted(ports)


def scan_systemd_units() -> list[str]:
    """Return active known systemd service units when systemctl is available."""
    exe = shutil.which("systemctl")
    if not exe:
        return []
    found: list[str] = []
    for unit in KNOWN_SYSTEMD_UNITS:
        try:
            if command([exe, "is-active", "--", unit], timeout=2).strip() == "active":
                found.append(unit)
        except (OSError, subprocess.SubprocessError):
            continue
    return found


def scan_docker_containers() -> list[str]:
    """Return running Docker container names when local Docker is reachable."""
    try:
        from selfheal.remediation.docker_adapter import DockerAdapter

        client = DockerAdapter().client()
        containers = client.containers.list()
        names: list[str] = []
        for c in containers:
            name = getattr(c, "name", "")
            if isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", name):
                names.append(name)
        return sorted(names)
    except Exception:  # noqa: BLE001
        return []


def parse_nginx_upstreams(conf_text: str) -> dict[str, list[str]]:
    """Extract upstream block names and proxy_pass targets from nginx config text."""
    upstreams: dict[str, list[str]] = {}
    for match in re.finditer(r"upstream\s+([A-Za-z0-9_.-]+)\s*\{([^}]*)\}", conf_text, re.DOTALL):
        name = _safe_service_name(match.group(1))
        servers = re.findall(r"server\s+([^\s;]+)", match.group(2))
        upstreams[name] = servers
    for match in re.finditer(r"proxy_pass\s+https?://([A-Za-z0-9_.-]+)(?::(\d+))?", conf_text):
        host = match.group(1)
        if host not in ("127.0.0.1", "localhost") and host not in upstreams:
            upstreams[_safe_service_name(host)] = [host]
    return upstreams


def scan_host(scan_dir: Path | None = None) -> tuple[Config, DiscoverySummary]:
    """Perform a bounded read-only scan of the host and optional directory."""
    summary = DiscoverySummary()
    summary.listening_ports = scan_listening_ports()
    summary.systemd_units = scan_systemd_units()
    summary.docker_containers = scan_docker_containers()

    by_name: dict[str, Service] = {}

    if scan_dir and scan_dir.is_dir():
        for log_path in sorted(scan_dir.glob("*.log"))[:20]:
            if log_path.is_file() and not log_path.is_symlink():
                resolved = str(log_path.resolve())
                summary.log_files.append(resolved)
                svc_name = _safe_service_name(log_path.stem)
                by_name[svc_name] = Service(
                    name=svc_name,
                    critical=_is_critical(svc_name),
                    logs=[resolved],
                )
        for nginx_candidate in [scan_dir / "nginx.conf", scan_dir / "etc" / "nginx" / "nginx.conf"]:
            if nginx_candidate.is_file() and not nginx_candidate.is_symlink():
                try:
                    text = nginx_candidate.read_text(encoding="utf-8", errors="replace")[:65536]
                    summary.nginx_upstreams.update(parse_nginx_upstreams(text))
                    resolved_cfg = str(nginx_candidate.resolve())
                    nginx_svc = by_name.get("nginx") or Service(name="nginx", critical=False)
                    if resolved_cfg not in nginx_svc.configs:
                        nginx_svc.configs.append(resolved_cfg)
                    by_name["nginx"] = nginx_svc
                except OSError:
                    pass

    for unit in summary.systemd_units:
        svc_name = _safe_service_name(unit.removesuffix(".service"))
        existing = by_name.get(svc_name)
        if existing:
            existing.journal_unit = unit
        else:
            by_name[svc_name] = Service(
                name=svc_name,
                critical=_is_critical(svc_name),
                journal_unit=unit,
            )

    for container in summary.docker_containers:
        compose_match = re.fullmatch(r"slime-demo-([A-Za-z0-9_.-]+)-\d+", container)
        svc_name = _safe_service_name(compose_match.group(1) if compose_match else container)
        demo_url = (
            "http://127.0.0.1:18081/"
            if compose_match and svc_name == "worker"
            else ("http://127.0.0.1:18080/" if compose_match else None)
        )
        existing = by_name.get(svc_name)
        if existing:
            existing.container_name = container
            if demo_url and not existing.http_url:
                existing.http_url = demo_url
        else:
            by_name[svc_name] = Service(
                name=svc_name,
                critical=_is_critical(svc_name),
                container_name=container,
                http_url=demo_url,
            )

    for upstream_name in summary.nginx_upstreams:
        if upstream_name not in by_name and upstream_name != "nginx":
            by_name[upstream_name] = Service(
                name=upstream_name,
                critical=_is_critical(upstream_name),
            )
        if "nginx" in by_name and upstream_name != "nginx":
            if upstream_name not in by_name["nginx"].depends_on:
                by_name["nginx"].depends_on.append(upstream_name)

    # Wire canonical nginx -> web -> worker dependency chain if discovered together
    if "web" in by_name and "worker" in by_name and "worker" not in by_name["web"].depends_on:
        by_name["web"].depends_on.append("worker")
    if "nginx" in by_name and "web" in by_name and "web" not in by_name["nginx"].depends_on:
        by_name["nginx"].depends_on.append("web")

    summary.services = list(by_name.values())
    anchor = (scan_dir or Path.cwd()).resolve().anchor or "/"
    config = Config(
        dry_run=True,
        disk_paths=[anchor],
        services=summary.services,
    )
    return config, summary
