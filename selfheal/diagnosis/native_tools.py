"""Read-only native diagnostics with exact configured path and endpoint authorization."""

import difflib
import json
import shutil
import socket
import sqlite3
from datetime import timedelta
from pathlib import Path
from urllib.parse import quote, urlparse

import httpx
import psutil

from selfheal.collectors.common import command
from selfheal.models import StrictModel, utcnow
from selfheal.safety.native_inventory import NativeInventory
from selfheal.safety.paths import PathAccess
from selfheal.security import sanitize


class NativeDiagnostics:
    """Does not receive an executor, action backend or write-enabled DB connection."""

    def __init__(self, inventory: NativeInventory) -> None:
        """Gather exact read allowlists; configuration baselines stay in redacted RAM."""
        self.inventory = inventory
        self.services = {s.name: s for s in inventory.config.services}
        self.config_paths = {p for s in self.services.values() for p in s.configs}
        self.paths = PathAccess([p for s in self.services.values() for p in s.logs + s.configs])
        self.disks = PathAccess(inventory.config.disk_paths)
        self.urls: set[str] = {s.http_url for s in self.services.values() if s.http_url is not None}
        self.ports: set[tuple[str, int]] = {
            (s.tcp_host, s.tcp_port)
            for s in self.services.values()
            if s.tcp_host is not None and s.tcp_port is not None
        }
        self.hosts: set[str] = {host for host, _ in self.ports} | {
            hostname for url in self.urls if (hostname := urlparse(url).hostname) is not None
        }
        self.baselines: dict[str, str] = {}

    def read(self, name: str, params: StrictModel) -> str:
        """Dispatch only read-only names, rejecting unknown destinations before IO."""
        p = params.model_dump()
        if name in {"tail_logs", "recent_changes"}:
            if p["service"] not in self.services:
                raise LookupError("unknown service")
            service = self.services[p["service"]]
            if name == "tail_logs":
                lines = []
                for path in service.logs[:4]:
                    text = self.paths.read(path, tail=True).decode("utf-8", errors="replace")
                    lines.extend(text.splitlines()[-p["n"] :])
                if not service.logs and service.journal_unit:
                    executable = shutil.which("journalctl")
                    if not executable:
                        raise RuntimeError("journalctl unavailable")
                    return command(
                        [
                            executable,
                            "--no-pager",
                            "-o",
                            "cat",
                            "-n",
                            str(p["n"]),
                            "--unit",
                            service.journal_unit,
                        ],
                        timeout=2,
                        limit=4096,
                    )
                if not service.logs and service.container_name:
                    container = self.inventory.docker.container(service.container_name)
                    stream = container.logs(tail=p["n"], stream=True, follow=False)
                    output = bytearray()
                    try:
                        for chunk in stream:
                            output.extend(chunk[: 4096 - len(output)])
                            if len(output) >= 4096:
                                break
                    finally:
                        close = getattr(stream, "close", None)
                        if close:
                            close()
                    return bytes(output).decode("utf-8", errors="replace")
                return "\n".join(lines[-p["n"] :])
            path = Path(self.inventory.config.database).absolute().as_posix()
            with sqlite3.connect(
                "file:" + quote(path, safe="/:") + "?mode=ro", uri=True
            ) as connection:
                cutoff = (utcnow() - timedelta(seconds=p["window"])).isoformat()
                rows = connection.execute(
                    "SELECT payload FROM events WHERE kind='change' AND service=? AND timestamp>=? ORDER BY timestamp DESC LIMIT 50",
                    (service.name, cutoff),
                ).fetchall()
            return json.dumps([json.loads(row[0]) for row in rows])[:16384]
        if name == "get_container_status":
            snapshot = self.inventory.snapshot(p["name"])
            if snapshot.kind != "container":
                raise LookupError("not a configured container")
            return json.dumps(
                {
                    "state": snapshot.state,
                    "healthy": snapshot.healthy,
                    "identity": snapshot.identity,
                }
            )
        if name == "check_port":
            if (p["host"], p["port"]) not in self.ports:
                raise LookupError("unknown endpoint")
            try:
                with socket.create_connection((p["host"], p["port"]), timeout=2):
                    return "port open"
            except OSError:
                return "port closed"
        if name == "disk_usage":
            disk_path = self.disks.authorize(p["path"])
            disk = psutil.disk_usage(str(disk_path))
            return json.dumps(
                {"total": disk.total, "used": disk.used, "free": disk.free, "percent": disk.percent}
            )
        if name == "top_processes":
            processes: list[dict[str, str | int | float]] = []
            for service in self.services.values():
                if service.process_pid:
                    try:
                        process = psutil.Process(service.process_pid)
                        processes.append(
                            {
                                "service": service.name,
                                "pid": process.pid,
                                "rss": process.memory_info().rss,
                                "cpu": process.cpu_percent(),
                            }
                        )
                    except psutil.Error:
                        continue
            return json.dumps(
                sorted(processes, key=lambda row: float(row["rss"]), reverse=True)[: p["n"]]
            )
        if name == "diff_config":
            if p["file"] not in self.config_paths:
                raise LookupError("unknown config")
            current = "\n".join(
                sanitize(line)
                for line in self.paths.read(p["file"])
                .decode("utf-8", errors="replace")
                .splitlines()
            )
            previous = self.baselines.setdefault(p["file"], current)
            if previous == current:
                return "No change versus redacted in-memory baseline (first call establishes baseline)."
            return "\n".join(
                difflib.unified_diff(
                    previous.splitlines(),
                    current.splitlines(),
                    fromfile="baseline",
                    tofile="current",
                )
            )
        if name == "http_probe":
            if p["url"] not in self.urls:
                raise LookupError("unknown HTTP target")
            url = urlparse(p["url"])
            if url.scheme not in {"http", "https"} or url.username or url.password:
                raise ValueError("credential-bearing or unsupported URL")
            with (
                httpx.Client(timeout=2, trust_env=False, follow_redirects=False) as client,
                client.stream("GET", p["url"]) as response,
            ):
                return json.dumps({"status_code": response.status_code})
        if name == "dns_check":
            if p["name"] not in self.hosts:
                raise LookupError("unknown DNS target")
            executable = shutil.which("nslookup")
            if not executable:
                raise RuntimeError("bounded DNS diagnostic requires nslookup")
            return command([executable, p["name"]], timeout=2, limit=4096)
        raise LookupError("unknown diagnostic tool")
