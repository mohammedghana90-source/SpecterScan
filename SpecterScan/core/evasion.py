"""
core/evasion.py
----------------
تقنيات تخفي إضافية فوق SYN scan الأساسي: Decoys (عناوين IP وهمية مرافقة)
وتجزئة الحزم (IP fragmentation). Pure Python بالكامل — يعيد استخدام دوال
core/packet.py مع تعديل قيم الحقول فقط، دون أي منطق بناء بايتات جديد هنا.

كلا الأسلوبين موثّقان ومعروفان (نظير -D و -f في nmap)، والهدف تعليمي بحت:
فهم كيف تُصمَّم تقنيات التخفي على مستوى الحزمة.
"""

from __future__ import annotations

import random
import socket

from core.packet import build_ip_header, build_tcp_syn_header, PacketBuildError, TCP_FLAG_SYN
from utils.logger import get_logger

log = get_logger("core.evasion")

# عناوين IP نتجنبها عند توليد decoys عشوائية: شبكات خاصة/محجوزة/loopback/multicast،
# حتى لا تبدو الـ decoys "مصطنعة بوضوح" لمراقِب يفحص عناوين المصدر.
_RESERVED_FIRST_OCTETS = {0, 10, 127, 169, 172, 192, 224, 240, 255}


class EvasionError(Exception):
    """أساس لاستثناءات هذه الوحدة (فشل توليد decoy صالح، معامل تجزئة غير منطقي...)."""


# ---------------------------------------------------------------------------
# Decoy Scanning
# ---------------------------------------------------------------------------

def generate_decoy_ips(count: int, *, exclude: set[str] | None = None) -> list[str]:
    """
    يولّد عناوين IPv4 عشوائية صالحة الصياغة لاستخدامها كعناوين مصدر مزيّفة
    (decoys)، مع تفادي:
        - النطاقات المحجوزة/الخاصة/multicast (حتى لا تبدو decoy واضحة الزيف).
        - أي عنوان في exclude (عادة: عنوان المصدر الحقيقي وعنوان الهدف نفسه).

    ملاحظة مهمة يجب توضيحها في التوثيق: هذه العناوين **لن تصلها أي ردود فعليًا**
    (الرد يذهب لصاحب العنوان الحقيقي، لا لنا) — الغرض فقط تشويش أي طرف يراقب
    حركة الشبكة الواردة للهدف، لا الحصول على معلومات إضافية منها.
    """
    if count <= 0:
        return []

    exclude = exclude or set()
    decoys: list[str] = []
    attempts = 0
    max_attempts = count * 20  # حد أعلى معقول لتفادي حلقة لا نهائية نظريًا

    while len(decoys) < count and attempts < max_attempts:
        attempts += 1
        first = random.randint(1, 223)
        if first in _RESERVED_FIRST_OCTETS:
            continue
        candidate = f"{first}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        if candidate in exclude or candidate in decoys:
            continue
        decoys.append(candidate)

    if len(decoys) < count:
        log.warning(
            "تعذّر توليد %d decoy فريد بعد %d محاولة — تم توليد %d فقط.",
            count, max_attempts, len(decoys),
        )

    return decoys


def build_decoy_burst(
    real_src_ip: str,
    dst_ip: str,
    real_src_port: int,
    dst_port: int,
    *,
    decoy_count: int,
    seq: int,
    ttl: int = 64,
    flags: int = TCP_FLAG_SYN,
    ack: int = 0,
) -> list[bytes]:
    """
    يبني قائمة حزم SYN جاهزة للإرسال: (decoy_count) حزمة بعناوين مصدر مزيّفة
    + حزمة واحدة حقيقية، بترتيب عشوائي داخل القائمة (بحيث لا تكون الحزمة
    الحقيقية دائمًا أول أو آخر واحدة — وإلا سهّلنا على المراقِب استبعاد الوهم).

    كل الحزم (الحقيقية والمزيّفة) تحمل **نفس seq و dst_port** عمدًا: هذا جزء
    من الخداع (تبدو كأنها كلها probes لنفس الفحص من مصادر مختلفة)، لكنه يعني
    أيضًا أن core/scanner.py سيتوقع ردًا واحدًا فقط مطابقًا فعليًا (القادم
    استجابةً للحزمة الحقيقية بالذات، لأنها الوحيدة التي تحمل عنوان مصدرنا
    الحقيقي فتصل الرد إلينا).
    """
    if decoy_count < 0:
        raise EvasionError(f"decoy_count لا يمكن أن يكون سالبًا: {decoy_count}")

    decoy_ips = generate_decoy_ips(decoy_count, exclude={real_src_ip, dst_ip})

    all_src_ips = decoy_ips + [real_src_ip]
    random.shuffle(all_src_ips)  # الحزمة الحقيقية تختلط عشوائيًا بين الـ decoys

    packets: list[bytes] = []
    for src_ip in all_src_ips:
        try:
            tcp_header = build_tcp_syn_header(
                real_src_port, dst_port, src_ip, dst_ip,
                seq=seq, ack=ack, flags=flags,
            )
            ip_header = build_ip_header(src_ip, dst_ip, len(tcp_header), ttl=ttl)
            packets.append(ip_header + tcp_header)
        except PacketBuildError as exc:
            log.warning("تعذّر بناء حزمة decoy بعنوان %s — تخطّي: %s", src_ip, exc)

    return packets


def send_decoy_burst(send_sock: socket.socket, dst_ip: str, packets: list[bytes]) -> None:
    """يرسل كل حزم الدفعة (decoys + الحزمة الحقيقية) بالتتابع عبر نفس raw socket."""
    for packet in packets:
        try:
            send_sock.sendto(packet, (dst_ip, 0))
        except OSError as exc:
            log.warning("فشل إرسال حزمة ضمن decoy burst إلى %s: %s", dst_ip, exc)


# ---------------------------------------------------------------------------
# IP Fragmentation
# ---------------------------------------------------------------------------

def build_fragmented_syn_packets(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    *,
    seq: int | None = None,
    ttl: int = 64,
    split_at: int = 8,
    flags: int = TCP_FLAG_SYN,
    ack: int = 0,
) -> list[bytes]:
    """
    يبني ترويسة TCP SYN كاملة (20 بايت) كالمعتاد، ثم يقسّمها على مستوى IP
    إلى جزأين (fragments)، بحيث لا تحتوي أي حزمة IP مفردة على ترويسة TCP
    كاملة — تقنية تفادي بسيطة لبعض أدوات الفحص التي تعتمد على مطابقة توقيع
    الحزمة الكاملة (نظير خيار -f في nmap).

    المعامل split_at: نقطة التقسيم داخل ترويسة TCP، **يجب أن تكون مضاعفًا
    لـ 8** (قيد فرضته مواصفة IP نفسها RFC 791: fragment offset يُقاس بوحدات
    8 بايت لا بايت مفرد). القيم الشائعة: 8 أو 16 (من أصل 20 بايت لترويسة TCP).

    يرجع قائمة من حزمتين (IP header + جزء) جاهزتين للإرسال بالترتيب،
    كلاهما يحملان نفس identification حتى يستطيع المستقبِل (أو حتى kernel
    محليًا) إعادة تجميعهما بشكل صحيح.
    """
    if split_at % 8 != 0:
        raise EvasionError(f"split_at يجب أن يكون مضاعفًا لـ 8 (قيد IP fragmentation): {split_at}")
    if not (0 < split_at < 20):
        raise EvasionError(f"split_at يجب أن يكون بين 1 و19 (طول ترويسة TCP 20 بايت): {split_at}")

    tcp_header = build_tcp_syn_header(src_port, dst_port, src_ip, dst_ip, seq=seq, ack=ack, flags=flags)
    part1, part2 = tcp_header[:split_at], tcp_header[split_at:]

    shared_identification = random.randint(0, 0xFFFF)

    fragment1 = build_ip_header(
        src_ip, dst_ip, len(part1), ttl=ttl,
        identification=shared_identification,
        more_fragments=True, fragment_offset=0,
    ) + part1

    fragment2 = build_ip_header(
        src_ip, dst_ip, len(part2), ttl=ttl,
        identification=shared_identification,
        more_fragments=False, fragment_offset=split_at // 8,
    ) + part2

    return [fragment1, fragment2]


def send_fragmented_syn(send_sock: socket.socket, dst_ip: str, fragments: list[bytes]) -> None:
    """يرسل أجزاء الحزمة المجزّأة بالترتيب الصحيح (الجزء الأول MF=1 ثم الأخير MF=0)."""
    for fragment in fragments:
        try:
            send_sock.sendto(fragment, (dst_ip, 0))
        except OSError as exc:
            log.warning("فشل إرسال fragment إلى %s: %s", dst_ip, exc)