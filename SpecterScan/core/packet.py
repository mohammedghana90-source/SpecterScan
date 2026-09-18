"""
core/packet.py
----------------
بناء ترويسات IP و TCP يدويًا (Pure Python — بدون أي مكتبة خارجية).

يعتمد فقط على:
    - struct   لتحويل الحقول إلى bytes بالترتيب الصحيح (Big-Endian / Network Byte Order)
    - socket   لتحويل عناوين IP النصية إلى صيغة binary (inet_aton) فقط - لا شيء آخر
    - random   لتوليد أرقام تسلسل (sequence numbers) و identification عشوائية

كل الدوال هنا "نقية" (pure): تأخذ مدخلات وترجع bytes، بدون أي I/O أو socket فعلي.
طبقة الإرسال الفعلية (raw socket) مسؤولية core/scanner.py.
"""

from __future__ import annotations

import random
import socket
import struct

# ---------------------------------------------------------------------------
# ثوابت البروتوكول
# ---------------------------------------------------------------------------

IP_VERSION = 4
IP_IHL = 5                      # Internet Header Length بوحدة 32-bit words (5 = 20 bytes, بدون Options)
IP_HEADER_LEN = IP_IHL * 4      # 20 بايت
TCP_HEADER_LEN = 20             # بدون TCP Options
TCP_DATA_OFFSET = 5             # بوحدة 32-bit words (5 = 20 bytes)

# TCP Flags (bitmask) - وثّقناها كاملة رغم أننا نستخدم SYN فقط حاليًا،
# لأن evasion.py و أي توسعة مستقبلية (مثل NULL/FIN/XMAS scan) ستحتاجها.
TCP_FLAG_FIN = 0x01
TCP_FLAG_SYN = 0x02
TCP_FLAG_RST = 0x04
TCP_FLAG_PSH = 0x08
TCP_FLAG_ACK = 0x10
TCP_FLAG_URG = 0x20


class PacketBuildError(Exception):
    """يُرفع عند فشل بناء حزمة بسبب مدخلات غير صالحة (IP غير صحيح، بورت خارج النطاق...)."""


# ---------------------------------------------------------------------------
# Checksum — خوارزمية RFC 791 / RFC 793 (one's complement)
# ---------------------------------------------------------------------------

def compute_checksum(data: bytes) -> int:
    """
    يحسب checksum بروتوكول IP/TCP القياسي (one's complement of one's complement sum).

    الخوارزمية (نفسها لـ IP header و TCP segment):
        1. اجمع كل 16-bit word في الـ data.
        2. إن كان هناك carry خارج حدود 16-bit، أضفه للمجموع (end-around carry).
        3. خذ الـ one's complement (اعكس البتات) للنتيجة النهائية.

    ملاحظة: إن كان طول data فرديًا، يُكمَّل بصفر بايت إضافي (padding) قبل الحساب،
    كما تنص المواصفة، دون أن يُعتبر هذا البايت جزءًا من البيانات الفعلية المُرسلة.
    """
    if len(data) % 2 == 1:
        data += b"\x00"

    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word
        # end-around carry: أي بت يتجاوز 16-bit يُطوى ويُضاف مجددًا
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    return (~checksum) & 0xFFFF


def _ipv4_to_bytes(ip_addr: str) -> bytes:
    """يحوّل عنوان IPv4 نصي (مثل '192.168.1.1') إلى 4 بايت binary."""
    try:
        return socket.inet_aton(ip_addr)
    except OSError as exc:
        raise PacketBuildError(f"عنوان IP غير صالح: {ip_addr!r}") from exc


# ---------------------------------------------------------------------------
# IP Header
# ---------------------------------------------------------------------------

def build_ip_header(
    src_ip: str,
    dst_ip: str,
    payload_len: int,
    *,
    ttl: int = 64,
    identification: int | None = None,
    protocol: int = socket.IPPROTO_TCP,
    dont_fragment: bool = False,
    more_fragments: bool = False,
    fragment_offset: int = 0,
) -> bytes:
    """
    يبني ترويسة IPv4 كاملة (20 بايت، بدون Options) مع checksum صحيح.

    المعاملات:
        src_ip, dst_ip   : عناوين IPv4 نصية.
        payload_len      : طول البيانات التي تأتي بعد ترويسة IP (مثلًا طول TCP segment).
        ttl              : Time To Live (افتراضي 64، شائع على Linux).
        identification   : معرّف الحزمة (16-bit)؛ إن لم يُحدَّد يُولَّد عشوائيًا.
                            **مهم لتجزئة الحزم (core/evasion.py):** كل الأجزاء
                            المنتمية لنفس الحزمة الأصلية يجب أن تحمل نفس القيمة،
                            وإلا لن يستطيع المستقبِل (أو حتى raw socket محليًا)
                            إعادة تجميعها.
        protocol         : رقم البروتوكول التالي (TCP=6 افتراضيًا).
        dont_fragment    : يضبط بت DF (Don't Fragment). افتراضيًا False.
        more_fragments   : يضبط بت MF (More Fragments) — True لكل الأجزاء
                            ما عدا الأخير في سلسلة حزم مجزّأة.
        fragment_offset  : الإزاحة بوحدة 8 بايت (وليس بايت مباشرة، حسب RFC 791) —
                            core/evasion.py مسؤول عن حساب هذه القيمة صحيحة.

    الحقول بالترتيب (RFC 791):
        Version(4) + IHL(4) | ToS(8) | Total Length(16)
        Identification(16)
        Flags(3) + Fragment Offset(13)
        TTL(8) | Protocol(8) | Header Checksum(16)
        Source Address(32)
        Destination Address(32)
    """
    if not (0 <= payload_len <= 0xFFFF - IP_HEADER_LEN):
        raise PacketBuildError(f"payload_len خارج النطاق المسموح: {payload_len}")
    if not (0 <= fragment_offset <= 0x1FFF):
        raise PacketBuildError(f"fragment_offset خارج النطاق المسموح (13-bit، 0-8191): {fragment_offset}")

    if identification is None:
        identification = random.randint(0, 0xFFFF)

    version_ihl = (IP_VERSION << 4) + IP_IHL
    tos = 0
    total_length = IP_HEADER_LEN + payload_len
    # ترتيب البتات حسب RFC 791: bit15=reserved(=0), bit14=DF, bit13=MF, bits12-0=offset
    flags_fragment_offset = (
        (int(dont_fragment) << 14)
        | (int(more_fragments) << 13)
        | (fragment_offset & 0x1FFF)
    )
    header_checksum = 0         # يُحسب لاحقًا، يبدأ من صفر
    src_bytes = _ipv4_to_bytes(src_ip)
    dst_bytes = _ipv4_to_bytes(dst_ip)

    # نبني الترويسة أولًا بـ checksum = 0 لحساب الـ checksum الصحيح عليها
    header_without_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        tos,
        total_length,
        identification,
        flags_fragment_offset,
        ttl,
        protocol,
        header_checksum,
        src_bytes,
        dst_bytes,
    )

    header_checksum = compute_checksum(header_without_checksum)

    # نعيد البناء بالـ checksum الصحيح في مكانه
    return struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        tos,
        total_length,
        identification,
        flags_fragment_offset,
        ttl,
        protocol,
        header_checksum,
        src_bytes,
        dst_bytes,
    )


# ---------------------------------------------------------------------------
# TCP Header (مع Pseudo-Header لحساب الـ checksum)
# ---------------------------------------------------------------------------

def _build_pseudo_header(src_ip: str, dst_ip: str, tcp_segment_len: int) -> bytes:
    """
    Pseudo-header مطلوب لحساب TCP checksum فقط (RFC 793) — لا يُرسَل فعليًا مع الحزمة،
    بل يُستخدم مؤقتًا كجزء من مدخل دالة compute_checksum.

    البنية: src_ip(32) + dst_ip(32) + zero(8) + protocol(8) + tcp_length(16)
    """
    return struct.pack(
        "!4s4sBBH",
        _ipv4_to_bytes(src_ip),
        _ipv4_to_bytes(dst_ip),
        0,
        socket.IPPROTO_TCP,
        tcp_segment_len,
    )


def build_tcp_syn_header(
    src_port: int,
    dst_port: int,
    src_ip: str,
    dst_ip: str,
    *,
    seq: int | None = None,
    ack: int = 0,
    flags: int = TCP_FLAG_SYN,
    window: int = 64240,
) -> bytes:
    """
    يبني ترويسة TCP (20 بايت، بدون Options) بعلم SYN افتراضيًا، مع checksum صحيح
    محسوب على pseudo-header + الترويسة نفسها (RFC 793).

    المعاملات:
        src_port, dst_port : أرقام المنافذ (0-65535).
        src_ip, dst_ip      : مطلوبة هنا فقط لحساب الـ checksum (pseudo-header)،
                               لا تُضمَّن فعليًا داخل ترويسة TCP نفسها.
        seq                 : رقم تسلسل ابتدائي؛ عشوائي إن لم يُحدَّد (كما توصي RFC لتفادي التنبؤ).
        ack                 : رقم التأكيد (0 دائمًا في SYN scan لأنه لا يوجد اتصال قائم).
        flags               : افتراضيًا SYN فقط؛ evasion.py قد يمرر تركيبات أخرى (FIN/XMAS/NULL scans).
        window              : حجم نافذة الاستقبال المُعلَنة.

    ملاحظة تصميمية: نُرجع دائمًا سيولة flags كما مُرِّرت دون تحقق صارم من صحة
    التركيبة (يمكن لاحقًا لطبقة أعلى في evasion.py أن ترسل تركيبات "غير منطقية"
    عمدًا كجزء من تقنيات التخفي المعروفة).
    """
    for name, port in (("src_port", src_port), ("dst_port", dst_port)):
        if not (0 <= port <= 0xFFFF):
            raise PacketBuildError(f"{name} خارج النطاق المسموح (0-65535): {port}")

    if seq is None:
        seq = random.randint(0, 0xFFFFFFFF)

    data_offset_reserved = TCP_DATA_OFFSET << 4   # الـ 4 بتات الأخيرة (reserved) تبقى صفرًا
    urgent_pointer = 0
    checksum = 0  # يُحسب لاحقًا

    tcp_header = struct.pack(
        "!HHLLBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        data_offset_reserved,
        flags,
        window,
        checksum,
        urgent_pointer,
    )

    pseudo_header = _build_pseudo_header(src_ip, dst_ip, len(tcp_header))
    checksum = compute_checksum(pseudo_header + tcp_header)

    return struct.pack(
        "!HHLLBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        data_offset_reserved,
        flags,
        window,
        checksum,
        urgent_pointer,
    )


# ---------------------------------------------------------------------------
# دالة مساعدة: تجميع حزمة SYN كاملة جاهزة للإرسال عبر raw socket
# ---------------------------------------------------------------------------

def build_syn_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    *,
    ttl: int = 64,
    seq: int | None = None,
) -> bytes:
    """
    يجمع IP header + TCP SYN header في حزمة واحدة جاهزة لـ raw socket مع IP_HDRINCL.
    هذه الدالة هي ما ستستدعيه core/scanner.py مباشرة لكل هدف (SYN scan فقط).

    (تبقى هذه الدالة كما هي للتوافق الخلفي؛ داخليًا تستدعي الآن
    build_tcp_probe_packet بأعلام SYN فقط.)
    """
    return build_tcp_probe_packet(
        src_ip, dst_ip, src_port, dst_port,
        flags=TCP_FLAG_SYN, seq=seq, ttl=ttl,
    )


def build_tcp_probe_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    *,
    flags: int,
    seq: int | None = None,
    ack: int = 0,
    ttl: int = 64,
) -> bytes:
    """
    نسخة عامة من build_syn_packet تقبل أي تركيبة أعلام TCP — تُستخدم لفحوصات
    التخفي الإضافية (core/scanner.py) التي تعتمد على استجابة الأهداف لحزم
    غير-SYN وفق RFC 793:

        - FIN scan   : flags = TCP_FLAG_FIN فقط.
        - NULL scan  : flags = 0 (بدون أي علم).
        - XMAS scan  : flags = FIN | PSH | URG (الحزمة "مضاءة" بالكامل).
        - ACK scan   : flags = TCP_FLAG_ACK فقط — يُستخدم لاكتشاف جدران
                       الحماية (filtered/unfiltered) وليس open/closed.
        - Window scan: نفس حزمة ACK scan، لكن التفسير يعتمد على حجم نافذة
                       استقبال الهدف في رد الـ RST (heuristic غير موثوق دائمًا).

    المعامل ack مفيد تحديدًا لـ ACK/Window scan: نضع فيه قيمة عشوائية
    نتحقق لاحقًا أن رقم seq في رد RST يطابقها (لأن الهدف — وفق RFC 793 —
    يردّ بـ <SEQ=SEG.ACK> عندما يكون علم ACK مضبوطًا في الحزمة الواردة).
    """
    tcp_header = build_tcp_syn_header(
        src_port, dst_port, src_ip, dst_ip,
        seq=seq, ack=ack, flags=flags,
    )
    ip_header = build_ip_header(src_ip, dst_ip, len(tcp_header), ttl=ttl)
    return ip_header + tcp_header


# ---------------------------------------------------------------------------
# التحليل (Parsing) — العملية العكسية للبناء، مطلوبة لتفسير الردود الواردة
# على raw receive socket في core/scanner.py (SYN-ACK / RST).
# ---------------------------------------------------------------------------

def _ipv4_to_str(raw4: bytes) -> str:
    return socket.inet_ntoa(raw4)


def parse_ip_header(packet: bytes) -> dict:
    """
    يفكّك أول ترويسة IPv4 من بداية packet ويرجع حقولها كـ dict، بالإضافة
    لحقل مساعد 'header_len' (بالبايت) و 'payload' (البيانات بعد ترويسة IP،
    أي TCP segment عادة).

    ملاحظة مهمة: يقرأ IHL الفعلي من الحزمة نفسها بدل افتراض 20 بايت دائمًا،
    لأن استجابات من مضيفين حقيقيين قد تحمل IP Options (نادر لكن ممكن)،
    فالافتراض الأعمى بطول 20 بايت كان سيكسر التحليل في تلك الحالة.
    """
    if len(packet) < 20:
        raise PacketBuildError(f"حزمة قصيرة جدًا لتحتوي ترويسة IP صالحة: {len(packet)} بايت")

    version_ihl, tos, total_length, identification, flags_fragment_offset, ttl, protocol, checksum, src_raw, dst_raw = (
        struct.unpack("!BBHHHBBH4s4s", packet[:20])
    )

    ihl = version_ihl & 0x0F
    header_len = ihl * 4

    if len(packet) < header_len:
        raise PacketBuildError(f"طول الحزمة ({len(packet)}) أقصر من IHL المعلن ({header_len})")

    return {
        "version": version_ihl >> 4,
        "header_len": header_len,
        "total_length": total_length,
        "identification": identification,
        "ttl": ttl,
        "protocol": protocol,
        "checksum": checksum,
        "src_ip": _ipv4_to_str(src_raw),
        "dst_ip": _ipv4_to_str(dst_raw),
        "payload": packet[header_len:total_length] if total_length else packet[header_len:],
    }


def parse_tcp_header(segment: bytes) -> dict:
    """
    يفكّك ترويسة TCP من بداية segment (بدون الحاجة لتفسير أي TCP Options —
    محرك المسح لا يحتاجها، يكتفي بالحقول الأساسية لمطابقة الردود).

    يرجع dict فيه أيضًا 'flags_set' كمجموعة أسماء أعلام مقروءة (مثل
    {'SYN', 'ACK'}) لتسهيل قراءتها في السجلات وطبقة المطابقة، بدل التعامل
    مع bitmask خام في كل مكان.
    """
    if len(segment) < TCP_HEADER_LEN:
        raise PacketBuildError(f"segment قصير جدًا ليحتوي ترويسة TCP صالحة: {len(segment)} بايت")

    src_port, dst_port, seq, ack, data_offset_reserved, flags, window, checksum, urgent_pointer = (
        struct.unpack("!HHLLBBHHH", segment[:TCP_HEADER_LEN])
    )

    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "seq": seq,
        "ack": ack,
        "data_offset": (data_offset_reserved >> 4) * 4,
        "flags": flags,
        "flags_set": decode_flags(flags),
        "window": window,
        "checksum": checksum,
    }


def decode_flags(flags: int) -> set[str]:
    """يحوّل bitmask أعلام TCP الخام إلى مجموعة أسماء مقروءة، للسجلات والتشخيص."""
    names = {
        TCP_FLAG_FIN: "FIN",
        TCP_FLAG_SYN: "SYN",
        TCP_FLAG_RST: "RST",
        TCP_FLAG_PSH: "PSH",
        TCP_FLAG_ACK: "ACK",
        TCP_FLAG_URG: "URG",
    }
    return {name for bit, name in names.items() if flags & bit}


# ---------------------------------------------------------------------------
# IPv6 (v1.2) — TCP segment فقط، بدون ترويسة IPv6 يدويًا
# ---------------------------------------------------------------------------
#
# ملاحظة تصميمية مهمة تختلف عن IPv4 أعلاه: في IPv4 نبني ترويسة IP يدويًا
# ونستخدم raw socket بخيار IP_HDRINCL لإرسالها كما هي (تحكم كامل بكل حقل).
# في IPv6، لا توجد آلية مكافئة مبسّطة ومضمونة عبر المنصات لتضمين ترويسة IPv6
# يدويًا على AF_INET6/SOCK_RAW/IPPROTO_TCP — بل السلوك المعياري على Linux
# هو: تُنشئ raw socket بعائلة AF_INET6 وبروتوكول IPPROTO_TCP، ترسل عبرها
# TCP segment فقط (بدون أي ترويسة IP)، والنواة (kernel) هي من يبني ترويسة
# IPv6 تلقائيًا اعتمادًا على عنوان الوجهة الممرَّر لـ sendto(). وعند
# الاستقبال، تصل البيانات أيضًا بدون ترويسة IPv6 (فقط TCP segment)،
# والحصول على عنوان المُرسِل يكون عبر recvfrom() لا من محتوى الحزمة نفسها.
#
# لذلك: لا توجد دالة "build_ipv6_header" هنا — فقط بناء TCP segment بـ
# checksum محسوب على pseudo-header الخاص بـ IPv6 (RFC 8200 §8.1)، والذي
# يختلف عن نظيره في IPv4 بطول العناوين (128-bit بدل 32-bit) وحقل الطول
# (32-bit بدل 16-bit).

IPV6_NEXT_HEADER_TCP = socket.IPPROTO_TCP  # = 6، نفس رقم IPv4


def _ipv6_to_bytes(ip_addr: str) -> bytes:
    """يحوّل عنوان IPv6 نصي (بما فيه الصيغ المختصرة مثل '::1') إلى 16 بايت binary."""
    try:
        return socket.inet_pton(socket.AF_INET6, ip_addr)
    except OSError as exc:
        raise PacketBuildError(f"عنوان IPv6 غير صالح: {ip_addr!r}") from exc


def _build_pseudo_header_v6(src_ip: str, dst_ip: str, tcp_segment_len: int) -> bytes:
    """
    Pseudo-header لحساب TCP checksum فوق IPv6 (RFC 8200 §8.1):
        src_ip(128) + dst_ip(128) + upper_layer_length(32) + zero(24) + next_header(8)
    """
    return struct.pack(
        "!16s16sI3xB",
        _ipv6_to_bytes(src_ip),
        _ipv6_to_bytes(dst_ip),
        tcp_segment_len,
        IPV6_NEXT_HEADER_TCP,
    )


def build_tcp_segment_v6(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    *,
    flags: int,
    seq: int | None = None,
    ack: int = 0,
    window: int = 64240,
) -> bytes:
    """
    يبني TCP segment (20 بايت، بدون Options) جاهزًا للإرسال مباشرة عبر
    raw socket بعائلة AF_INET6 — بدون أي ترويسة IPv6 (انظر الشرح أعلاه).

    نفس منطق build_tcp_syn_header لكن مع pseudo-header مبني لـ IPv6، لأن
    checksum بروتوكول TCP يعتمد على عناوين الشبكة (IPv4 أو IPv6) رغم أنها
    لا تُرسَل فعليًا ضمن TCP segment نفسه.
    """
    for name, port in (("src_port", src_port), ("dst_port", dst_port)):
        if not (0 <= port <= 0xFFFF):
            raise PacketBuildError(f"{name} خارج النطاق المسموح (0-65535): {port}")

    if seq is None:
        seq = random.randint(0, 0xFFFFFFFF)

    data_offset_reserved = TCP_DATA_OFFSET << 4
    urgent_pointer = 0
    checksum = 0

    tcp_header = struct.pack(
        "!HHLLBBHHH",
        src_port, dst_port, seq, ack,
        data_offset_reserved, flags, window, checksum, urgent_pointer,
    )

    pseudo_header = _build_pseudo_header_v6(src_ip, dst_ip, len(tcp_header))
    checksum = compute_checksum(pseudo_header + tcp_header)

    return struct.pack(
        "!HHLLBBHHH",
        src_port, dst_port, seq, ack,
        data_offset_reserved, flags, window, checksum, urgent_pointer,
    )