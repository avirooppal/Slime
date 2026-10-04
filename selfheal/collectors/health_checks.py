"""Read-only configured HTTP, TCP, process and systemd health checks."""

import shutil
import socket
import subprocess
from urllib.parse import urlparse

import httpx
import psutil

from selfheal.collectors.common import command
from selfheal.config import Service
from selfheal.models import Event, Kind


class Health:
    """Probe a configured service without redirects or ambient proxy variables."""

    def __init__(self, service: Service) -> None:
        """Retain only explicit health targets."""
        self.service = service

    def collect(self) -> list[Event]:
        """Bound each probe; health failures are evidence rather than exceptions."""
        results: list[tuple[str, bool]] = []
        s = self.service
        if s.http_url:
            url = urlparse(s.http_url)
            if url.scheme not in {"http", "https"} or url.username or url.password:
                raise ValueError("HTTP endpoint must use http(s) without embedded credentials")
            try:
                with (
                    httpx.Client(timeout=3, follow_redirects=False, trust_env=False) as client,
                    client.stream("GET", s.http_url) as response,
                ):
                    results.append(("http", 200 <= response.status_code < 300))
            except httpx.HTTPError:
                results.append(("http", False))
        if s.tcp_host and s.tcp_port:
            try:
                with socket.create_connection((s.tcp_host, s.tcp_port), timeout=3):
                    results.append(("tcp", True))
            except OSError:
                results.append(("tcp", False))
        if s.process_pid:
            try:
                process = psutil.Process(s.process_pid)
                healthy = process.is_running() and process.status() != psutil.STATUS_ZOMBIE
            except psutil.Error:
                healthy = False
            results.append(("process", healthy))
        if s.journal_unit:
            executable = shutil.which("systemctl")
            if executable:
                try:
                    healthy = (
                        command([executable, "is-active", "--", s.journal_unit]).strip() == "active"
                    )
                except (OSError, subprocess.SubprocessError):
                    healthy = False
                results.append(("systemd", healthy))
        return [
            Event(
                kind=Kind.HEALTH,
                service=s.name,
                source=name,
                severity="info" if healthy else "warning",
                attributes={"healthy": healthy},
            )
            for name, healthy in results
        ]
