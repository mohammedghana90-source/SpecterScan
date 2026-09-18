"""Service identification and banner collection for SpecterScan.

Uses only Python's standard library. It never executes remote commands and is
intended for hosts that the operator is authorized to assess.
"""
from __future__ import annotations

import asyncio
import re
import socket
from contextlib import asynccontextmanager
from dataclasses import dataclass

COMMON_SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http", 110: "pop3",
    111: "rpcbind", 123: "ntp", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
    587: "submission", 631: "ipp", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle", 2049: "nfs", 2375: "docker", 3000: "http-alt", 3306: "mysql",
    3389: "rdp", 5000: "http-alt", 5432: "postgresql", 5900: "vnc", 6379: "redis",
    8000: "http-alt", 8080: "http-proxy", 18080: "http-alt", 8443: "https-alt", 9200: "elasticsearch",
}

@dataclass(slots=True)
class ServiceInfo:
    service: str | None = None
    banner: str | None = None
    version: str | None = None


# ---------------------------------------------------------------------------
# Connection pooling
# ---------------------------------------------------------------------------
#
# Service/banner detection can run for hundreds of open ports at once after a
# large scan. Without a limit, that turns into hundreds of simultaneous
# outbound TCP connections fired in the same instant — hard on the local
# machine's ephemeral-port/file-descriptor budget, and on the scanned host if
# many of those open ports happen to live on it. ConnectionPool caps
# concurrency both globally and per target host while still letting
# independent hosts proceed in parallel.

class ConnectionPool:
    """asyncio-friendly concurrency limiter for service-detection connections."""

    def __init__(self, max_total: int = 100, max_per_host: int = 20):
        if max_total <= 0:
            raise ValueError("max_total يجب أن تكون أكبر من صفر")
        if max_per_host <= 0:
            raise ValueError("max_per_host يجب أن تكون أكبر من صفر")

        self._global_sem = asyncio.Semaphore(max_total)
        self._host_sems: dict[str, asyncio.Semaphore] = {}
        self._max_per_host = max_per_host

    def _host_semaphore(self, host: str) -> asyncio.Semaphore:
        sem = self._host_sems.get(host)
        if sem is None:
            sem = asyncio.Semaphore(self._max_per_host)
            self._host_sems[host] = sem
        return sem

    @asynccontextmanager
    async def acquire(self, host: str):
        async with self._global_sem, self._host_semaphore(host):
            yield


# Module-level default pool used when callers don't supply their own —
# keeps the simple call pattern (`inspect_service(host, port)`) working for
# scripts/tests that don't care about tuning concurrency.
_DEFAULT_POOL = ConnectionPool()


def identify_service(port: int, banner: str | None = None, registry=None) -> str | None:
    text = (banner or "").lower()

    if registry is not None:
        for pattern, service in registry.patterns:
            if re.search(pattern, text):
                return service

    patterns = [
        (r"openssh|dropbear", "ssh"), (r"nginx", "http"), (r"apache", "http"),
        (r"microsoft-iis", "http"), (r"vsftpd|proftpd|ftp", "ftp"),
        (r"mysql", "mysql"), (r"postgres", "postgresql"), (r"redis", "redis"),
        (r"smtp|postfix|exim", "smtp"), (r"imap", "imap"), (r"samba|smb", "smb"),
    ]
    for pattern, service in patterns:
        if re.search(pattern, text):
            return service

    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]

    if registry is not None and port in registry.port_map:
        return registry.port_map[port]

    return None

async def grab_banner(
    host: str,
    port: int,
    timeout: float = 2.0,
    pool: ConnectionPool | None = None,
    registry=None,
) -> str | None:
    """Collect a small protocol banner without sending credentials or payloads.
    إن قدّم registry (core/plugins.py) دوال probe مخصصة، تُجرَّب أولًا؛ أول
    نتيجة غير None تُستخدم مباشرة دون تجربة منطق الـ TCP العام أدناه."""

    if registry is not None and registry.probes:
        for custom_probe in registry.probes:
            try:
                result = await custom_probe(host, port, timeout)
            except Exception as exc:  # noqa: BLE001 - عزل خطأ plugin واحد عن الفحص نفسه
                log_plugin_error(custom_probe, exc)
                continue
            if result:
                return result

    pool = pool or _DEFAULT_POOL
    writer = None
    try:
        async with pool.acquire(host):
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
            if port in (80, 3000, 5000, 8000, 8080):
                writer.write(b"HEAD / HTTP/1.0\r\nHost: specterscan\r\nConnection: close\r\n\r\n")
                await writer.drain()
            elif port == 443 or port == 8443:
                # Plain TCP greeting is intentionally used; TLS negotiation is not attempted here.
                pass
            try:
                data = await asyncio.wait_for(reader.read(512), timeout=timeout)
            except asyncio.TimeoutError:
                data = b""
        if not data:
            return None
        text = data.decode("utf-8", errors="replace")
        return " ".join(text.split())[:512]
    except (OSError, asyncio.TimeoutError):
        return None
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


def log_plugin_error(probe_fn, exc: Exception) -> None:
    name = getattr(probe_fn, "__name__", repr(probe_fn))
    from utils.logger import get_logger
    get_logger("core.plugins").warning("فشل probe مخصص %r: %s", name, exc)


async def inspect_service(
    host: str,
    port: int,
    timeout: float = 2.0,
    do_banner: bool = True,
    pool: ConnectionPool | None = None,
    registry=None,
) -> ServiceInfo:
    banner = await grab_banner(host, port, timeout, pool=pool, registry=registry) if do_banner else None
    return ServiceInfo(service=identify_service(port, banner, registry=registry), banner=banner)
