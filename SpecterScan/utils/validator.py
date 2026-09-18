from __future__ import annotations
import ipaddress
import re

class ValidationError(Exception):
    pass

# أكبر عدد مضيفين نسمح بتوسيعه تلقائيًا من شبكة CIDR واحدة. IPv4 يسمح بنطاق
# أوسع نسبيًا (شبكات /16 وأصغر شائعة في الاستخدام المشروع)، أما IPv6 فحتى
# /116 (4096 عنوان) يُعتبر سخيًا فعليًا — شبكة /64 عادية تحتوي 2^64 عنوان،
# وأي محاولة توسيعها ستستهلك كل الذاكرة المتاحة فورًا دون أي فائدة فحص حقيقية.
MAX_IPV4_HOSTS = 65536       # يغطي حتى /16
MAX_IPV6_HOSTS = 4096        # يغطي حتى /116 تقريبًا؛ لعناوين أكبر استخدم /128 فرديًا

# فحص صيغة hostname بسيط (RFC 1123)، بدون أي استعلام DNS فعلي هنا — الحل
# الفعلي (resolve_hostname) مسؤولية core/scanner.py، هذه الدالة تتحقق من
# الشكل فقط حتى لا نرفض hostnames صالحة كانت ستُقبل سابقًا (كانت هذه الدالة
# ترفض أي شيء ليس IP/CIDR، رغم أن README ونواة الفحص يدعمان hostname صراحة).
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)


def _looks_like_hostname(value: str) -> bool:
    return "/" not in value and bool(_HOSTNAME_RE.match(value))


def validate_target(target: str) -> None:
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError as exc:
        if _looks_like_hostname(target):
            return
        raise ValidationError(
            f"الهدف غير صالح: {target!r} — استخدم عنوان IPv4/IPv6 أو شبكة CIDR أو hostname صالح"
        ) from exc

    if net.version == 4 and net.num_addresses > MAX_IPV4_HOSTS:
        raise ValidationError(
            f"شبكة IPv4 كبيرة جدًا ({net.num_addresses} عنوان) — الحد الأقصى المدعوم "
            f"{MAX_IPV4_HOSTS} عنوان لكل عملية فحص. استخدم نطاقًا أصغر."
        )

    if net.version == 6 and net.num_addresses > MAX_IPV6_HOSTS:
        raise ValidationError(
            f"شبكة IPv6 كبيرة جدًا ({net.num_addresses} عنوان) — الحد الأقصى المدعوم "
            f"{MAX_IPV6_HOSTS} عنوان لكل عملية فحص (فضاء عناوين IPv6 هائل، لا يمكن تعداده "
            "بالكامل). استخدم /116 أو أصغر، أو عنوانًا فرديًا."
        )

def validate_ports(ports_spec: str) -> None:
    if not ports_spec or not ports_spec.strip():
        raise ValidationError("يجب تحديد منفذ واحد على الأقل")
    for part in ports_spec.split(","):
        part = part.strip()
        if not part:
            raise ValidationError(f"صيغة المنافذ غير صحيحة: {ports_spec!r}")
        if "-" in part:
            bounds = part.split("-")
            if len(bounds) != 2:
                raise ValidationError(f"صيغة نطاق منافذ غير صحيحة: {part!r}")
            _validate_single_port_str(bounds[0], ports_spec)
            _validate_single_port_str(bounds[1], ports_spec)
            if int(bounds[0]) > int(bounds[1]):
                raise ValidationError(f"نطاق منافذ غير منطقي: {part!r}")
        else:
            _validate_single_port_str(part, ports_spec)

def _validate_single_port_str(value: str, original_spec: str) -> None:
    if not value.isdigit():
        raise ValidationError(f"رقم منفذ غير صحيح: {value!r} في {original_spec!r}")
    port = int(value)
    if not 1 <= port <= 65535:
        raise ValidationError(f"رقم المنفذ خارج النطاق 1-65535: {port}")

def validate_options(opts) -> None:
    validate_target(opts.target)
    validate_ports(opts.ports)
    if opts.rate <= 0: raise ValidationError(f"--rate يجب أن تكون أكبر من صفر: {opts.rate}")
    if opts.timeout <= 0: raise ValidationError(f"--timeout يجب أن تكون أكبر من صفر: {opts.timeout}")
    if opts.decoys < 0: raise ValidationError("--decoys لا يمكن أن تكون سالبة")
    if opts.retries < 0: raise ValidationError("--retries لا يمكن أن تكون سالبة")
    if opts.workers <= 0: raise ValidationError("--workers يجب أن تكون أكبر من صفر")
    if opts.output not in ("text", "json", "html", "csv"):
        raise ValidationError("صيغة الإخراج المتاحة: text, json, html, csv")
    valid_scan_types = ("syn", "connect", "udp", "fin", "null", "xmas", "ack", "window")
    if opts.scan_type not in valid_scan_types:
        raise ValidationError(
            "نوع الفحص المتاح: " + ", ".join(valid_scan_types)
        )
    if opts.fragment and opts.scan_type != "syn":
        raise ValidationError("--fragment متاح مع SYN scan فقط")
    if opts.decoys and opts.scan_type != "syn":
        raise ValidationError("--decoys متاح مع SYN scan فقط")
    if opts.decoys and opts.fragment:
        raise ValidationError("لا تستخدم --decoys و--fragment معًا في نفس الفحص")
    if (opts.service_detection or opts.banner) and opts.scan_type not in ("syn", "connect", "window"):
        raise ValidationError(
            "--service-detection/--banner يتطلبان منفذًا يمكن تأكيد أنه open "
            "(متاحان مع syn أو connect أو window scan فقط)"
        )
