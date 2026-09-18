"""SpecterScan scanning engine.

Core capabilities:
- IPv4 TCP SYN scanning with raw sockets
- TCP connect scanning
- UDP probing
- hostname / IPv4 / CIDR target support
- asyncio concurrency, rate limiting and retries
- per-response packet matching
- optional decoys and IPv4 fragmentation for SYN mode
- lightweight OS fingerprint heuristic
- optional service/banner enrichment
"""

from __future__ import annotations

import asyncio
import ipaddress
import platform
import random
import socket
import time
from dataclasses import dataclass
from enum import Enum

from core.packet import (
    build_syn_packet,
    build_tcp_probe_packet,
    build_tcp_segment_v6,
    parse_ip_header,
    parse_tcp_header,
    TCP_FLAG_FIN,
    TCP_FLAG_SYN,
    TCP_FLAG_RST,
    TCP_FLAG_PSH,
    TCP_FLAG_ACK,
    TCP_FLAG_URG,
    PacketBuildError,
)
from core import evasion
from core.service_detector import inspect_service
from utils.logger import get_logger
from utils.validator import MAX_IPV4_HOSTS, MAX_IPV6_HOSTS


log = get_logger("core.scanner")

RECV_BUFFER_SIZE = 65535
EPHEMERAL_PORT_RANGE = (49152, 65535)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class ScannerError(Exception):
    """Base scanner exception."""


class UnsupportedPlatformError(ScannerError):
    """Raised when raw SYN scanning is not available."""


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

class PortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"
    UNFILTERED = "unfiltered"   # ACK scan فقط: يعني "لا يوجد جدار حماية يحجب المنفذ"
                                 # (لا علاقة له بكون المنفذ مفتوحًا أو مغلقًا فعليًا)


# ---------------------------------------------------------------------------
# أنواع فحوصات TCP الخفية المبنية فوق raw sockets (فحص SYN الأساسي + الفحوصات
# الإضافية من مرحلة v1.1). كل نوع يحدد الأعلام المُرسَلة، وما هو التفسير
# الصحيح عند عدم استلام أي رد إطلاقًا (RFC 793: منفذ مفتوح خلف جدار حماية
# صامت لا يمكن تمييزه عن منفذ مفتوح فعليًا في هذه الفحوصات الأربعة الأخيرة).
# ---------------------------------------------------------------------------

STEALTH_SCAN_FLAGS: dict[str, int] = {
    "syn": TCP_FLAG_SYN,
    "fin": TCP_FLAG_FIN,
    "null": 0,
    "xmas": TCP_FLAG_FIN | TCP_FLAG_PSH | TCP_FLAG_URG,
    "ack": TCP_FLAG_ACK,
    "window": TCP_FLAG_ACK,
}

# الفحوصات التي لا يمكن تمييز "مفتوح" عن "مُصفّى بصمت" فيها عند عدم الرد.
_NO_RESPONSE_STATE: dict[str, PortState] = {
    "syn": PortState.FILTERED,
    "fin": PortState.OPEN_FILTERED,
    "null": PortState.OPEN_FILTERED,
    "xmas": PortState.OPEN_FILTERED,
    "ack": PortState.FILTERED,
    "window": PortState.FILTERED,
}

# الفحوصات التي يُستخدم فيها حقل seq (وليس ack) في الرد للمطابقة، لأن حزمة
# الفحص نفسها تحمل علم ACK (فوفق RFC 793 يردّ الهدف بـ <SEQ=SEG.ACK>).
_SEQ_MATCHED_SCAN_TYPES = {"ack", "window"}


@dataclass
class ScanResult:
    host: str
    port: int
    state: PortState
    protocol: str = "tcp"
    latency_ms: float | None = None
    ttl: int | None = None
    window: int | None = None
    os_guess: str | None = None
    service: str | None = None
    banner: str | None = None
    hostname: str | None = None
    attempts: int = 1


# ---------------------------------------------------------------------------
# Target handling
# ---------------------------------------------------------------------------

def detect_platform_support() -> None:
    if platform.system() == "Windows":
        raise UnsupportedPlatformError(
            "SYN Stealth Scan عبر raw sockets غير مدعوم مباشرة على Windows. "
            "استخدم Linux/Kali/Ubuntu أو WSL2 لاختبار SYN."
        )


def resolve_hostname(hostname: str) -> list[str]:
    """يحلّ اسم مضيف إلى عناوين IPv4 و/أو IPv6 (AF_UNSPEC) — أي عنوان صالح
    من أي عائلة تُرجعه النواة نأخذه؛ الطبقات الأعلى (raw scan) تقرر لاحقًا
    عائلة واحدة للتشغيل الفعلي (انظر ملاحظة الفحص المختلط أدناه)."""

    try:
        infos = socket.getaddrinfo(
            hostname,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise ScannerError(
            f"تعذر حل اسم المضيف: {hostname!r}"
        ) from exc

    addresses = sorted(
        {
            info[4][0]
            for info in infos
            if info[4] and info[4][0]
        }
    )

    if not addresses:
        raise ScannerError(
            f"لم يتم العثور على عنوان IP للمضيف: {hostname!r}"
        )

    return addresses


def expand_targets(target_spec: str) -> list[str]:
    """Expand IPv4/IPv6, CIDR, or hostname into target IP addresses.

    Examples:
        192.168.8.112
        192.168.8.0/24
        2001:db8::1
        2001:db8::/120
        scanme.nmap.org
    """

    target_spec = target_spec.strip()

    if not target_spec:
        raise ScannerError("الهدف فارغ.")

    # ---------------------------------------------------------
    # First: try IPv4/IPv6 / CIDR (كلاهما مدعوم عبر ipaddress.ip_network)
    # ---------------------------------------------------------

    try:
        network = ipaddress.ip_network(target_spec, strict=False)

        if network.version == 4 and network.num_addresses > MAX_IPV4_HOSTS:
            raise ScannerError(
                f"شبكة IPv4 كبيرة جدًا ({network.num_addresses} عنوان) — "
                f"الحد الأقصى {MAX_IPV4_HOSTS}."
            )
        if network.version == 6 and network.num_addresses > MAX_IPV6_HOSTS:
            raise ScannerError(
                f"شبكة IPv6 كبيرة جدًا ({network.num_addresses} عنوان) — "
                f"الحد الأقصى {MAX_IPV6_HOSTS}. استخدم /116 أو أصغر، أو عنوانًا فرديًا."
            )

        if network.num_addresses == 1:
            return [str(network.network_address)]

        return [str(ip) for ip in network.hosts()] or [
            str(network.network_address)
        ]

    except ValueError:
        pass

    # ---------------------------------------------------------
    # Second: treat it as hostname
    # ---------------------------------------------------------

    # Prevent obviously malformed values from reaching DNS.
    if "/" in target_spec:
        raise ScannerError(
            f"الهدف غير صالح: {target_spec!r} — استخدم IPv4/IPv6 أو شبكة CIDR "
            "أو hostname صالح."
        )

    return resolve_hostname(target_spec)


def ip_version(ip: str) -> int:
    """يرجع 4 أو 6 حسب عائلة العنوان."""
    return ipaddress.ip_address(ip).version


# ---------------------------------------------------------------------------
# Ports
# ---------------------------------------------------------------------------

def expand_ports(ports_spec: str) -> list[int]:
    ports: set[int] = set()

    for part in ports_spec.split(","):
        part = part.strip()

        if not part:
            continue

        try:
            if "-" in part:
                start_text, end_text = part.split("-", 1)

                start = int(start_text)
                end = int(end_text)

                if not (0 <= start <= 65535 and 0 <= end <= 65535):
                    raise ValueError

                if start > end:
                    raise ValueError

                ports.update(range(start, end + 1))

            else:
                port = int(part)

                if not 0 <= port <= 65535:
                    raise ValueError

                ports.add(port)

        except ValueError as exc:
            raise ScannerError(
                f"منفذ غير صالح: {part!r}"
            ) from exc

    if not ports:
        raise ScannerError("لم يتم تحديد أي منافذ صالحة.")

    return sorted(ports)


# ---------------------------------------------------------------------------
# Scan preparation
# ---------------------------------------------------------------------------

def build_randomized_target_list(
    targets: list[str],
    ports: list[int],
) -> list[tuple[str, int]]:
    pairs = [
        (ip, port)
        for ip in targets
        for port in ports
    ]

    random.shuffle(pairs)

    return pairs


def get_local_ip_for_target(dst_ip: str) -> str:
    family = socket.AF_INET6 if ip_version(dst_ip) == 6 else socket.AF_INET
    probe = socket.socket(family, socket.SOCK_DGRAM)

    try:
        probe.connect((dst_ip, 1))
        return probe.getsockname()[0]

    finally:
        probe.close()


# ---------------------------------------------------------------------------
# Raw sockets
# ---------------------------------------------------------------------------

def create_send_socket() -> socket.socket:
    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_RAW,
        socket.IPPROTO_RAW,
    )

    sock.setsockopt(
        socket.IPPROTO_IP,
        socket.IP_HDRINCL,
        1,
    )

    return sock


def create_recv_socket() -> socket.socket:
    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_RAW,
        socket.IPPROTO_TCP,
    )

    sock.setblocking(False)

    return sock


def create_send_socket_v6() -> socket.socket:
    """راوح-سوكِت IPv6 للإرسال: بخلاف IPv4، لا نضبط أي خيار HDRINCL — النواة
    تبني ترويسة IPv6 تلقائيًا من عنوان الوجهة الممرَّر إلى sendto() (انظر
    الشرح في core/packet.py أعلى build_tcp_segment_v6)."""
    return socket.socket(
        socket.AF_INET6,
        socket.SOCK_RAW,
        socket.IPPROTO_TCP,
    )


def create_recv_socket_v6() -> socket.socket:
    sock = socket.socket(
        socket.AF_INET6,
        socket.SOCK_RAW,
        socket.IPPROTO_TCP,
    )

    sock.setblocking(False)

    return sock


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

class RateLimiter:
    """محدِّد معدّل إرسال بسيط (token-bucket بفاصل ثابت)، مع دعم اختياري
    لتخفيض المعدّل تلقائيًا عند ارتفاع نسبة الفقد (adaptive)."""

    def __init__(self, packets_per_second: int, adaptive: bool = False):
        if packets_per_second <= 0:
            raise ValueError(
                "packets_per_second يجب أن تكون أكبر من صفر"
            )

        self._base_interval = 1.0 / packets_per_second
        self._interval = self._base_interval
        self._lock = asyncio.Lock()
        self._next = 0.0

        self._adaptive = adaptive
        self._sent = 0
        self._lost = 0

    async def wait(self) -> None:
        async with self._lock:
            now = time.monotonic()

            if now < self._next:
                await asyncio.sleep(self._next - now)

            self._next = max(now, self._next) + self._interval

    def report_result(self, lost: bool) -> None:
        """يُستدعى من ScanEngine بعد كل مسبار لتحديث نسبة الفقد. إن كان
        adaptive=True، يبطّئ المعدّل تدريجيًا حين تتجاوز نسبة الفقد 20%
        (خطوة x1.5 في الفاصل)، ويعيده تدريجيًا نحو المعدّل الأصلي حين تنخفض
        نسبة الفقد عن 5% (خطوة x0.9)، مع سقف أعلى لا يتجاوز 5x المعدّل
        الأصلي حتى لا "يتجمد" الفحص عمليًا على شبكة سيئة جدًا."""

        if not self._adaptive:
            return

        self._sent += 1
        if lost:
            self._lost += 1

        # نقيّم كل 20 مسبارًا فقط لتفادي تذبذب الفاصل على عيّنات صغيرة جدًا.
        if self._sent < 20 or self._sent % 20 != 0:
            return

        loss_ratio = self._lost / self._sent

        if loss_ratio > 0.20:
            self._interval = min(
                self._interval * 1.5,
                self._base_interval * 5,
            )
        elif loss_ratio < 0.05:
            self._interval = max(
                self._interval * 0.9,
                self._base_interval,
            )


# ---------------------------------------------------------------------------
# OS heuristic
# ---------------------------------------------------------------------------

def guess_os_from_response(ttl: int, window: int) -> str:
    if ttl <= 64:
        base = "Linux/Unix (heuristic)"
    elif ttl <= 128:
        base = "Windows (heuristic)"
    else:
        base = "Network device/Other (heuristic)"

    if window == 65535 and ttl <= 64:
        return base + " [low confidence]"

    return base


# ---------------------------------------------------------------------------
# Pending SYN probe
# ---------------------------------------------------------------------------

@dataclass
class _PendingProbe:
    host: str
    port: int
    expected_acks: set[int]
    future: asyncio.Future
    sent_at: float
    attempts: int = 1


# ---------------------------------------------------------------------------
# SYN scan engine
# ---------------------------------------------------------------------------

class ScanEngine:
    def __init__(
        self,
        targets_ports: list[tuple[str, int]],
        src_ip: str,
        src_port: int,
        rate_limiter: RateLimiter,
        timeout: float,
        decoys: int = 0,
        retries: int = 0,
        workers: int = 100,
        fragmented: bool = False,
        scan_type: str = "syn",
    ):
        self._queue = list(targets_ports)

        self._src_ip = src_ip
        self._src_port = src_port

        self._rate = rate_limiter
        self._timeout = timeout

        self._decoys = decoys
        self._retries = retries
        self._workers = max(1, workers)
        self._fragmented = fragmented

        if scan_type not in STEALTH_SCAN_FLAGS:
            raise ScannerError(f"نوع فحص غير مدعوم في ScanEngine: {scan_type!r}")

        self._scan_type = scan_type
        self._probe_flags = STEALTH_SCAN_FLAGS[scan_type]
        # ACK/Window scan يرسلان علم ACK بأنفسهما، لذا الرد (RST بلا ACK عادةً)
        # يُطابَق عبر حقل seq الخاص به (=قيمة ACK التي أرسلناها)، وليس حقل ack.
        self._match_field = "seq" if scan_type in _SEQ_MATCHED_SCAN_TYPES else "ack"

        self._family = ip_version(src_ip)

        if self._family == 6 and (decoys or fragmented):
            raise ScannerError(
                "الـ decoys وIP fragmentation غير مدعومَين على IPv6 حاليًا "
                "(v1.2) — راجع README لمزيد من التفاصيل."
            )

        self._pending: dict[
            tuple[str, int],
            _PendingProbe,
        ] = {}

        self._results: list[ScanResult] = []

        self._send_sock: socket.socket | None = None
        self._recv_sock: socket.socket | None = None

        self.stats = {
            "packets_sent": 0,
            "packets_received": 0,
            "packets_lost": 0,
        }

    async def run(self) -> list[ScanResult]:
        if self._family == 6:
            self._send_sock = create_send_socket_v6()
            self._recv_sock = create_recv_socket_v6()
        else:
            self._send_sock = create_send_socket()
            self._recv_sock = create_recv_socket()

        receiver = asyncio.create_task(
            self._receive_loop()
        )

        try:
            sem = asyncio.Semaphore(self._workers)

            async def guarded(pair):
                async with sem:
                    return await self._probe(
                        pair[0],
                        pair[1],
                    )

            await asyncio.gather(
                *(guarded(pair) for pair in self._queue)
            )

        finally:
            receiver.cancel()

            try:
                await receiver
            except asyncio.CancelledError:
                pass

            if self._send_sock:
                self._send_sock.close()

            if self._recv_sock:
                self._recv_sock.close()

        return sorted(
            self._results,
            key=lambda r: (
                r.host,
                r.port,
                r.protocol,
            ),
        )

    # ---------------------------------------------------------
    # Send SYN
    # ---------------------------------------------------------

    def _send_probe(
        self,
        host: str,
        port: int,
        seq: int,
        ack: int = 0,
    ) -> None:
        """يبني حزمة/حزم الفحص ويرسلها. decoys وfragmentation مسموحان مع أي
        scan_type يستخدم أعلام قابلة للتجزئة/التمويه على IPv4 فقط (يفرضه
        utils/validator.py و__init__ أعلاه لـ IPv6)."""

        if self._family == 6:
            self._send_probe_v6(host, port, seq, ack)
            return

        if self._fragmented:
            packets = evasion.build_fragmented_syn_packets(
                self._src_ip,
                host,
                self._src_port,
                port,
                seq=seq,
                ack=ack,
                flags=self._probe_flags,
            )

        elif self._decoys:
            packets = evasion.build_decoy_burst(
                self._src_ip,
                host,
                self._src_port,
                port,
                decoy_count=self._decoys,
                seq=seq,
                ack=ack,
                flags=self._probe_flags,
            )

        else:
            packets = [
                build_tcp_probe_packet(
                    self._src_ip,
                    host,
                    self._src_port,
                    port,
                    flags=self._probe_flags,
                    seq=seq,
                    ack=ack,
                )
            ]

        for packet in packets:
            if self._send_sock is None:
                raise OSError("Send socket غير جاهز.")

            self._send_sock.sendto(
                packet,
                (host, 0),
            )

            self.stats["packets_sent"] += 1

    def _send_probe_v6(
        self,
        host: str,
        port: int,
        seq: int,
        ack: int,
    ) -> None:
        """إرسال IPv6: لا ترويسة IP يدوية — فقط TCP segment (انظر شرح
        build_tcp_segment_v6 في core/packet.py). لا دعم لـ decoys/fragmentation
        هنا (مرفوض مسبقًا في __init__)."""

        segment = build_tcp_segment_v6(
            self._src_ip,
            host,
            self._src_port,
            port,
            flags=self._probe_flags,
            seq=seq,
            ack=ack,
        )

        if self._send_sock is None:
            raise OSError("Send socket غير جاهز.")

        # عنوان IPv6 في sendto يحتاج 4-tuple: (host, port, flowinfo, scope_id)
        self._send_sock.sendto(segment, (host, 0, 0, 0))
        self.stats["packets_sent"] += 1

    # ---------------------------------------------------------
    # SYN probe
    # ---------------------------------------------------------

    async def _probe(
        self,
        host: str,
        port: int,
    ) -> None:

        key = (host, port)
        loop = asyncio.get_running_loop()

        expected_acks: set[int] = set()
        pending: _PendingProbe | None = None

        try:
            for attempt in range(
                1,
                self._retries + 2,
            ):
                seq = random.randint(
                    0,
                    0xFFFFFFFF,
                )

                if self._match_field == "seq":
                    # ACK/Window scan: seq مُرسَل عشوائي بلا معنى، وقيمة ACK
                    # التي نضعها هي ما سنطابق رد الهدف (حقل seq فيه) عليه.
                    ack_value = random.randint(0, 0xFFFFFFFF)
                    expected_acks.add(ack_value)
                elif self._scan_type == "syn":
                    ack_value = 0
                    expected_acks.add((seq + 1) & 0xFFFFFFFF)
                else:
                    # FIN/NULL/XMAS: لا علم ACK لدينا، فالهدف (إن كان المنفذ
                    # مغلقًا) يردّ بـ <ACK=SEG.SEQ> لأن SEG.LEN=0.
                    ack_value = 0
                    expected_acks.add(seq)

                future = loop.create_future()

                pending = _PendingProbe(
                    host,
                    port,
                    expected_acks,
                    future,
                    time.monotonic(),
                    attempt,
                )

                self._pending[key] = pending

                try:
                    await self._rate.wait()

                    self._send_probe(
                        host,
                        port,
                        seq,
                        ack_value,
                    )

                    try:
                        response = await asyncio.wait_for(
                            asyncio.shield(future),
                            timeout=self._timeout,
                        )

                    except asyncio.TimeoutError:
                        response = None

                    if response is not None:
                        self._rate.report_result(lost=False)
                        self._results.append(response)
                        return

                    self._rate.report_result(lost=True)

                except (
                    OSError,
                    PacketBuildError,
                    evasion.EvasionError,
                ) as exc:

                    log.debug(
                        "SYN probe failed for %s:%s: %s",
                        host,
                        port,
                        exc,
                    )

                    if attempt == self._retries + 1:
                        self._results.append(
                            ScanResult(
                                host,
                                port,
                                _NO_RESPONSE_STATE[self._scan_type],
                                attempts=attempt,
                            )
                        )
                        return

            self.stats["packets_lost"] += 1

            self._results.append(
                ScanResult(
                    host,
                    port,
                    _NO_RESPONSE_STATE[self._scan_type],
                    attempts=self._retries + 1,
                )
            )

        finally:
            if self._pending.get(key) is pending:
                self._pending.pop(
                    key,
                    None,
                )

    # ---------------------------------------------------------
    # Receive loop
    # ---------------------------------------------------------

    async def _receive_loop(self) -> None:
        while True:
            try:
                if self._recv_sock is None:
                    return

                if self._family == 6:
                    raw, addr = self._recv_sock.recvfrom(
                        RECV_BUFFER_SIZE
                    )
                else:
                    raw = self._recv_sock.recv(
                        RECV_BUFFER_SIZE
                    )
                    addr = None

            except BlockingIOError:
                await asyncio.sleep(0.001)
                continue

            except OSError:
                return

            self.stats["packets_received"] += 1

            if self._family == 6:
                # AF_INET6 SOCK_RAW/IPPROTO_TCP على Linux يسلّم TCP segment
                # فقط (بدون ترويسة IPv6) — عنوان المُرسِل يأتي من recvfrom لا
                # من محتوى الحزمة (انظر شرح core/packet.py).
                self._handle_incoming_v6(raw, addr[0])
            else:
                self._handle_incoming(raw)

    # ---------------------------------------------------------
    # Incoming packet matching (IPv4)
    # ---------------------------------------------------------

    def _handle_incoming(
        self,
        raw: bytes,
    ) -> None:

        try:
            ip_info = parse_ip_header(raw)

            if ip_info.get("protocol") != socket.IPPROTO_TCP:
                return

            tcp_info = parse_tcp_header(
                ip_info["payload"]
            )

        except PacketBuildError:
            return

        if (
            ip_info["dst_ip"] != self._src_ip
            or tcp_info["dst_port"] != self._src_port
        ):
            return

        self._match_and_resolve(ip_info["src_ip"], ip_info, tcp_info)

    # ---------------------------------------------------------
    # Incoming packet matching (IPv6)
    # ---------------------------------------------------------

    def _handle_incoming_v6(
        self,
        raw: bytes,
        src_ip: str,
    ) -> None:

        try:
            tcp_info = parse_tcp_header(raw)
        except PacketBuildError:
            return

        if tcp_info["dst_port"] != self._src_port:
            return

        # لا يوجد TTL/hop-limit متاح بدون ancillary data (cmsg) هنا، فنضعه
        # None صراحة بدل تخمين قيمة — OS heuristic يتخطّى الحالة تلقائيًا.
        ip_info = {"ttl": None, "src_ip": src_ip}

        self._match_and_resolve(src_ip, ip_info, tcp_info)

    # ---------------------------------------------------------
    # مطابقة الرد بمسبار معلَّق + حساب النتيجة (مشترك بين v4/v6)
    # ---------------------------------------------------------

    def _match_and_resolve(
        self,
        src_ip: str,
        ip_info: dict,
        tcp_info: dict,
    ) -> None:

        for probe_key, probe in list(
            self._pending.items()
        ):

            if probe.host != src_ip:
                continue

            if (
                tcp_info[self._match_field]
                not in probe.expected_acks
            ):
                continue

            if probe.future.done():
                continue

            latency = (
                time.monotonic() - probe.sent_at
            ) * 1000

            flags = tcp_info["flags"]
            result = self._interpret_response(
                probe,
                flags,
                ip_info,
                tcp_info,
                round(latency, 2),
            )

            if result is not None:
                probe.future.set_result(result)

            return

    def _interpret_response(
        self,
        probe: "_PendingProbe",
        flags: int,
        ip_info: dict,
        tcp_info: dict,
        latency_ms: float,
    ) -> "ScanResult | None":
        """يفسّر الرد الوارد حسب نوع الفحص الحالي (self._scan_type)، ويعيد
        ScanResult جاهزة، أو None إن لم يكن الرد حاسمًا (نادر، يُبقي المسبار
        منتظرًا حتى انتهاء المهلة)."""

        common = dict(
            latency_ms=latency_ms,
            ttl=ip_info["ttl"],
            window=tcp_info["window"],
            attempts=probe.attempts,
        )

        if self._scan_type == "syn":
            # SYN + ACK = مفتوح
            if flags & TCP_FLAG_SYN and flags & TCP_FLAG_ACK:
                return ScanResult(
                    probe.host, probe.port, PortState.OPEN,
                    os_guess=(
                        guess_os_from_response(
                            ip_info["ttl"], tcp_info["window"],
                        )
                        if ip_info.get("ttl") is not None
                        else None  # IPv6: لا TTL/hop-limit متاح بدون ancillary data
                    ),
                    **common,
                )
            if flags & TCP_FLAG_RST:
                return ScanResult(
                    probe.host, probe.port, PortState.CLOSED, **common,
                )
            return None

        if self._scan_type in ("fin", "null", "xmas"):
            # RST = مغلق. عدم الرد (يُعالَج عبر timeout في _probe) = open|filtered.
            if flags & TCP_FLAG_RST:
                return ScanResult(
                    probe.host, probe.port, PortState.CLOSED, **common,
                )
            return None

        if self._scan_type == "ack":
            # أي RST يصل يعني أن المنفذ غير محجوب بجدار حماية (unfiltered)،
            # بصرف النظر عن كونه مفتوحًا أو مغلقًا فعليًا (ACK scan لا يميّز ذلك).
            if flags & TCP_FLAG_RST:
                return ScanResult(
                    probe.host, probe.port, PortState.UNFILTERED, **common,
                )
            return None

        if self._scan_type == "window":
            # نفس مبدأ ACK scan، لكن نستخدم حجم نافذة الاستقبال في رد RST
            # كتخمين (heuristic غير موثوق على كل الأنظمة) لتمييز open/closed:
            # نافذة غير صفرية على بعض الأنظمة (BSD قديمة مثلاً) تلمّح لمنفذ مفتوح.
            if flags & TCP_FLAG_RST:
                state = (
                    PortState.OPEN
                    if tcp_info["window"] > 0
                    else PortState.CLOSED
                )
                return ScanResult(
                    probe.host, probe.port, state, **common,
                )
            return None

        return None

    def _find_port(
        self,
        host: str,
        ack: int,
    ) -> int | None:

        for (h, p), probe in self._pending.items():
            if (
                h == host
                and ack in probe.expected_acks
            ):
                return p

        return None


# ---------------------------------------------------------------------------
# Result enrichment
# ---------------------------------------------------------------------------

def _enrich_results(
    results: list[ScanResult],
    resolve: bool,
    service_detection: bool,
    banner: bool,
    timeout: float,
    pool_size: int = 100,
    plugins_dir: str | None = "plugins",
) -> None:

    from core.service_detector import ConnectionPool
    from core.plugins import load_plugins

    pool = ConnectionPool(
        max_total=max(1, pool_size),
        max_per_host=min(20, max(1, pool_size)),
    )
    registry = load_plugins(plugins_dir) if (service_detection or banner) else None

    async def enrich_one(
        result: ScanResult,
    ) -> None:

        if resolve:
            try:
                hostname_info = await asyncio.to_thread(
                    socket.gethostbyaddr,
                    result.host,
                )

                result.hostname = hostname_info[0]

            except (
                OSError,
                socket.herror,
            ):
                result.hostname = None

        if (
            result.state == PortState.OPEN
            and result.protocol == "tcp"
            and service_detection
        ):
            info = await inspect_service(
                result.host,
                result.port,
                timeout,
                banner,
                pool=pool,
                registry=registry,
            )

            result.service = info.service
            result.banner = info.banner

    async def runner():
        await asyncio.gather(
            *(enrich_one(r) for r in results)
        )

    asyncio.run(runner())


# ---------------------------------------------------------------------------
# TCP connect scan
# ---------------------------------------------------------------------------

async def _connect_probe(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    rate: RateLimiter,
) -> ScanResult:

    last_attempt = 0
    start = time.monotonic()

    for attempt in range(
        1,
        retries + 2,
    ):

        last_attempt = attempt

        try:
            await rate.wait()

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host,
                    port,
                ),
                timeout=timeout,
            )

            writer.close()

            try:
                await writer.wait_closed()
            except Exception:
                pass

            return ScanResult(
                host,
                port,
                PortState.OPEN,
                latency_ms=round(
                    (time.monotonic() - start) * 1000,
                    2,
                ),
                attempts=attempt,
            )

        except ConnectionRefusedError:

            return ScanResult(
                host,
                port,
                PortState.CLOSED,
                latency_ms=round(
                    (time.monotonic() - start) * 1000,
                    2,
                ),
                attempts=attempt,
            )

        except (
            asyncio.TimeoutError,
            OSError,
        ):
            continue

    return ScanResult(
        host,
        port,
        PortState.FILTERED,
        attempts=last_attempt,
    )


# ---------------------------------------------------------------------------
# UDP scan
# ---------------------------------------------------------------------------

async def _udp_probe(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    rate: RateLimiter,
) -> ScanResult:

    loop = asyncio.get_running_loop()
    start = time.monotonic()

    for attempt in range(
        1,
        retries + 2,
    ):

        transport = None

        try:
            await rate.wait()

            response_future = loop.create_future()

            class P(asyncio.DatagramProtocol):

                def connection_made(
                    self,
                    transport_,
                ):
                    nonlocal transport

                    transport = transport_

                    transport.sendto(
                        b"\x00"
                    )

                def datagram_received(
                    self,
                    data,
                    addr,
                ):
                    if not response_future.done():
                        response_future.set_result(True)

                def error_received(
                    self,
                    exc,
                ):
                    if not response_future.done():
                        response_future.set_result(False)

                def connection_lost(
                    self,
                    exc,
                ):
                    if (
                        exc
                        and not response_future.done()
                    ):
                        response_future.set_result(False)

            transport, protocol = (
                await loop.create_datagram_endpoint(
                    P,
                    remote_addr=(
                        host,
                        port,
                    ),
                )
            )

            try:
                response = await asyncio.wait_for(
                    response_future,
                    timeout=timeout,
                )

            except asyncio.TimeoutError:
                response = None

            finally:
                transport.close()

            if response is True:
                return ScanResult(
                    host,
                    port,
                    PortState.OPEN,
                    protocol="udp",
                    latency_ms=round(
                        (time.monotonic() - start) * 1000,
                        2,
                    ),
                    attempts=attempt,
                )

            if response is False:
                return ScanResult(
                    host,
                    port,
                    PortState.CLOSED,
                    protocol="udp",
                    attempts=attempt,
                )

        except OSError as exc:
            log.debug(
                "UDP probe failed for %s:%d (attempt %d): %s",
                host,
                port,
                attempt,
                exc,
            )

            if transport:
                transport.close()

    return ScanResult(
        host,
        port,
        PortState.OPEN_FILTERED,
        protocol="udp",
        attempts=retries + 1,
    )


# ---------------------------------------------------------------------------
# Non-raw scan dispatcher
# ---------------------------------------------------------------------------

async def _run_async_nonraw(
    pairs,
    scan_type,
    timeout,
    retries,
    rate,
    workers,
):

    sem = asyncio.Semaphore(
        max(1, workers)
    )

    async def one(
        host,
        port,
    ):

        async with sem:

            if scan_type == "connect":
                return await _connect_probe(
                    host,
                    port,
                    timeout,
                    retries,
                    rate,
                )

            return await _udp_probe(
                host,
                port,
                timeout,
                retries,
                rate,
            )

    return await asyncio.gather(
        *(one(h, p) for h, p in pairs)
    )


# ---------------------------------------------------------------------------
# Host discovery
# ---------------------------------------------------------------------------

async def discover_hosts(
    targets: list[str],
    timeout: float = 0.7,
    workers: int = 100,
) -> list[str]:

    probes = (
        22,
        80,
        443,
        3000,
        5000,
        8000,
        8080,
    )

    sem = asyncio.Semaphore(
        max(1, workers)
    )

    async def one(host):

        async with sem:

            for port in probes:

                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(
                            host,
                            port,
                        ),
                        timeout=timeout,
                    )

                    writer.close()

                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass

                    return host

                except (
                    OSError,
                    asyncio.TimeoutError,
                ):
                    continue

            return None

    found = await asyncio.gather(
        *(one(h) for h in targets)
    )

    return [
        h
        for h in found
        if h
    ]


# ---------------------------------------------------------------------------
# Main scan entry point
# ---------------------------------------------------------------------------

def execute_scan(opts) -> dict:
    """ينفّذ الفحص فعليًا ويرجع النتائج الخام (dict) دون أي طباعة أو كتابة
    تقرير — هذا ما يفصلها عن run_scan() أدناه (المخصصة لـ CLI فقط)، ويسمح
    بإعادة استخدامها من أي واجهة أخرى (REST API في api.py، أو استخدام برمجي
    مباشر لـ core.scanner دون المرور بـ CLI إطلاقًا).

    يرجع dict بالمفاتيح: target, scan_type, targets (بعد التوسيع/الاكتشاف)،
    results (قائمة ScanResult)، stats، duration (بالثواني).
    """

    scan_type = getattr(
        opts,
        "scan_type",
        "syn",
    )

    targets = expand_targets(
        opts.target
    )

    ports = expand_ports(
        opts.ports
    )

    log.info(
        "Resolved target %s -> %s",
        opts.target,
        ", ".join(targets),
    )

    # ---------------------------------------------------------
    # Optional host discovery
    # ---------------------------------------------------------

    if (
        getattr(opts, "discover_hosts", False)
        and len(targets) > 1
    ):

        targets = asyncio.run(
            discover_hosts(
                targets,
                min(
                    opts.timeout,
                    1.0,
                ),
                getattr(
                    opts,
                    "workers",
                    100,
                ),
            )
        )

        if not targets:
            return {
                "target": opts.target,
                "scan_type": scan_type,
                "targets": [],
                "results": [],
                "stats": {"discovered_hosts": 0},
                "duration": 0.0,
            }

    # ---------------------------------------------------------
    # Build target/port pairs
    # ---------------------------------------------------------

    pairs = build_randomized_target_list(
        targets,
        ports,
    )

    start = time.monotonic()

    # ---------------------------------------------------------
    # SYN / FIN / NULL / XMAS / ACK / Window scans (كلها raw sockets،
    # تختلف فقط في الأعلام المُرسَلة وتفسير الرد — انظر ScanEngine)
    # ---------------------------------------------------------

    if scan_type in STEALTH_SCAN_FLAGS:

        detect_platform_support()

        target_families = {ip_version(t) for t in targets}
        if len(target_families) > 1:
            raise ScannerError(
                "لا يمكن خلط أهداف IPv4 وIPv6 في نفس عملية الفحص الخام "
                f"({scan_type}) — شغّل الفحص لكل عائلة على حدة."
            )

        src_ip = get_local_ip_for_target(
            targets[0]
        )

        src_port = random.randint(
            *EPHEMERAL_PORT_RANGE
        )

        engine = ScanEngine(
            pairs,
            src_ip,
            src_port,
            RateLimiter(
                opts.rate,
                adaptive=getattr(opts, "adaptive_rate", False),
            ),
            opts.timeout,
            decoys=getattr(
                opts,
                "decoys",
                0,
            ),
            retries=getattr(
                opts,
                "retries",
                0,
            ),
            workers=getattr(
                opts,
                "workers",
                100,
            ),
            fragmented=getattr(
                opts,
                "fragment",
                False,
            ),
            scan_type=scan_type,
        )

        results = asyncio.run(
            engine.run()
        )

        stats = engine.stats

    # ---------------------------------------------------------
    # Connect / UDP
    # ---------------------------------------------------------

    else:

        results = asyncio.run(
            _run_async_nonraw(
                pairs,
                scan_type,
                opts.timeout,
                getattr(
                    opts,
                    "retries",
                    0,
                ),
                RateLimiter(opts.rate),
                getattr(
                    opts,
                    "workers",
                    100,
                ),
            )
        )

        stats = {
            "packets_sent": len(pairs),
            "packets_received": 0,
            "packets_lost": 0,
        }

    # ---------------------------------------------------------
    # Service/banner enrichment
    # ---------------------------------------------------------

    _enrich_results(
        results,
        getattr(
            opts,
            "resolve",
            False,
        ),
        getattr(
            opts,
            "service_detection",
            False,
        )
        or getattr(
            opts,
            "banner",
            False,
        ),
        getattr(
            opts,
            "banner",
            False,
        ),
        opts.timeout,
        getattr(
            opts,
            "workers",
            100,
        ),
        getattr(
            opts,
            "plugins_dir",
            "plugins",
        ),
    )

    duration = (
        time.monotonic() - start
    )

    return {
        "target": opts.target,
        "scan_type": scan_type,
        "targets": targets,
        "results": results,
        "stats": stats,
        "duration": duration,
    }


def run_scan(opts) -> int:
    """واجهة CLI فوق execute_scan(): تنفّذ الفحص ثم تطبع/تكتب التقرير
    (utils/reporter.py) وترجع exit code. أي استخدام برمجي آخر (REST API
    مثلًا) يجب أن يستدعي execute_scan() مباشرة بدل هذه الدالة."""

    outcome = execute_scan(opts)

    from utils.reporter import emit_report

    emit_report(
        outcome["results"],
        getattr(
            opts,
            "output",
            "text",
        ),
        target=outcome["target"],
        scan_type=outcome["scan_type"],
        duration=outcome["duration"],
        stats=outcome["stats"],
        path=getattr(
            opts,
            "report",
            None,
        ),
    )

    return 0

