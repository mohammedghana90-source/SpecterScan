#!/usr/bin/env python3
"""
specterscan.py
----------------
نقطة الدخول الرئيسية لأداة SpecterScan + واجهة سطر الأوامر (CLI).

هذا الملف مسؤول فقط عن:
    1. تعريف واجهة CLI (argparse) وتحليل المدخلات.
    2. تحميل ودمج ملف الإعدادات (config.json) مع قيم CLI.
    3. تهيئة نظام السجلات (utils.logger).
    4. معالجة الأخطاء المركزية - كل استثناء متوقع يتحول لرسالة واحدة واضحة
       للمستخدم، بدل تسريب traceback خام (حسب متطلب المشروع).
    5. تفويض التنفيذ الفعلي لطبقة core (scanner.py) - هذا الملف نفسه لا
       يحتوي أي منطق شبكي.

تشغيل الأداة:
    python specterscan.py scan 192.168.1.1 --ports 1-1000
    python specterscan.py --version
    python specterscan.py --config myconfig.json scan 10.0.0.0/24
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field

from utils.logger import setup_logging, get_logger
from utils.validator import ValidationError, validate_options

__version__ = "1.2.0"

# رمز الخروج القياسي المستخدم لكل حالات الفشل المتوقعة (إدخال خاطئ، صلاحيات،
# ملف تالف...). نستخدم رمزًا واحدًا ثابتًا (1) لتبسيط الفحص من سكربتات خارجية؛
# لو احتجنا تمييز أدق لاحقًا يمكن توسعتها لرموز متعددة موثّقة في README.
EXIT_OK = 0
EXIT_ERROR = 1

DEFAULT_CONFIG_PATH = "config.json"

log = get_logger("cli")


# ---------------------------------------------------------------------------
# استثناءات مخصصة لطبقة CLI/التهيئة (تختلف عن PacketBuildError في core.packet،
# وستنضم لاحقًا لاستثناءات core.scanner ضمن معالج مركزي واحد في main()).
# ---------------------------------------------------------------------------

class ConfigError(Exception):
    """يُرفع عند مشكلة في تحميل أو تفسير ملف الإعدادات (غير موجود / JSON تالف)."""


# ملاحظة: ValidationError لم يعد يُعرَّف هنا — أصبح في utils/validator.py
# (مستورد أعلاه)، بحيث يبقى هذا الملف مقتصرًا على تعريف CLI وتنسيق التنفيذ.


# ---------------------------------------------------------------------------
# نموذج الإعدادات الموحّد بعد الدمج (CLI + config.json)
# ---------------------------------------------------------------------------

@dataclass
class ScanOptions:
    """تمثيل موحّد لخيارات المسح بعد دمج config.json مع وسائط CLI (الأولوية لـ CLI)."""

    target: str
    ports: str = "1-1000"
    rate: int = 500
    timeout: float = 2.0
    output: str = "text"          # text | json | html | csv
    log_level: str = "INFO"
    scan_type: str = "syn"
    retries: int = 1
    workers: int = 100
    decoys: int = 0
    fragment: bool = False
    adaptive_rate: bool = False
    plugins_dir: str = "plugins"
    service_detection: bool = False
    banner: bool = False
    resolve: bool = False
    report: str | None = None
    discover_hosts: bool = False
    extra: dict = field(default_factory=dict)  # أي مفاتيح إضافية من config.json غير معروفة، لعرضها في DEBUG فقط


# ---------------------------------------------------------------------------
# تحميل ودمج الإعدادات
# ---------------------------------------------------------------------------

def load_config_file(path: str) -> dict:
    """
    يحمّل ملف config.json ويرجع محتواه كـ dict.

    يرفع ConfigError برسالة واحدة واضحة في حالتين محددتين في متطلبات المشروع:
        - الملف غير موجود.
        - الملف موجود لكنه JSON تالف (غير قابل للتحليل).
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError as exc:
        raise ConfigError(f"ملف الإعدادات غير موجود: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(
            f"ملف الإعدادات تالف أو بصيغة JSON غير صحيحة: {path} "
            f"(السطر {exc.lineno}, العمود {exc.colno})"
        ) from exc
    except PermissionError as exc:
        raise ConfigError(f"لا توجد صلاحية كافية لقراءة ملف الإعدادات: {path}") from exc


def merge_options(cli_args: argparse.Namespace, config_dict: dict) -> ScanOptions:
    """
    يدمج القيم القادمة من config.json مع قيم CLI، بحيث تفوز قيمة CLI دائمًا
    إن كانت قد مُرِّرت صراحة من المستخدم (وليست مجرد قيمة argparse الافتراضية).

    الآلية: نعتمد على أن القيم الافتراضية في argparse لكل خيار = None، وبالتالي
    "مُرِّر من المستخدم" يعني ببساطة "القيمة ليست None" بعد التحليل.

    تحقق من الأنواع (Type Coercion): قيم CLI مضمونة النوع فعليًا لأن argparse
    يطبّق type=int/float بنفسه على --rate/--timeout/--decoys. لكن قيم
    config.json تأتي من JSON خام (json.load يقبل أي نوع صالح JSON-syntactically:
    "rate": "fast" مثلًا يمر بدون خطأ من json.load نفسه رغم أنه غير منطقي هنا).
    لذلك كل قيمة قادمة من config.json تُمرّ إجباريًا عبر _coerce() هنا، بحيث
    أي خطأ نوع (لا رقم صالح لحقل رقمي مثلًا) يتحول لـ ConfigError برسالة واحدة
    واضحة الآن، بدل TypeError/ValueError غامض يظهر لاحقًا أثناء المسح الفعلي.
    """
    # (اسم الحقل -> دالة تحويل النوع المتوقع لهذا الحقل تحديدًا)
    field_casters = {
        "ports": str,
        "rate": int,
        "timeout": float,
        "decoys": int,
        "output": str,
        "log_level": str,
        "scan_type": str,
        "retries": int,
        "workers": int,
        "fragment": bool,
        "adaptive_rate": bool,
        "plugins_dir": str,
        "service_detection": bool,
        "banner": bool,
        "resolve": bool,
        "report": str,
        "discover_hosts": bool,
    }
    merged: dict = {}

    for field_name, caster in field_casters.items():
        cli_value = getattr(cli_args, field_name, None)
        if cli_value is not None:
            merged[field_name] = cli_value          # من argparse: النوع مضمون مسبقًا
        elif field_name in config_dict:
            merged[field_name] = _coerce(config_dict[field_name], caster, field_name)

    extra = {k: v for k, v in config_dict.items() if k not in field_casters}

    return ScanOptions(target=cli_args.target, extra=extra, **merged)


def _coerce(raw_value, caster, field_name: str):
    if caster is bool:
        if isinstance(raw_value, bool):
            return raw_value
        if isinstance(raw_value, str) and raw_value.strip().lower() in {"true", "1", "yes", "on"}:
            return True
        if isinstance(raw_value, str) and raw_value.strip().lower() in {"false", "0", "no", "off"}:
            return False
        raise ConfigError(f"قيمة منطقية غير صالحة للحقل {field_name!r}: {raw_value!r}")
    """يحوّل قيمة خام من config.json إلى النوع المتوقع، أو يرفع ConfigError برسالة واضحة."""
    try:
        return caster(raw_value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(
            f"قيمة غير صالحة لحقل {field_name!r} في ملف الإعدادات: {raw_value!r} "
            f"(المتوقع نوع قابل للتحويل إلى {caster.__name__})"
        ) from exc


# ---------------------------------------------------------------------------
# بناء واجهة argparse
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    """
    ملاحظة تصميمية مهمة (ونتيجة اختبار فعلي، ليست افتراضًا نظريًا):
    --config و --log-level مُعرَّفان **مرة واحدة فقط**، على الـ parser
    الرئيسي، ولا يُعاد تعريفهما على scan_parser.

    جربنا في البداية نمط argparse "parents=" الشائع لجعل هذين الخيارين
    صالحين قبل أو بعد اسم subcommand، لكن اختبار فعلي كشف مشكلة حقيقية:
    عند تكرار نفس الـ action (نفس dest) على الـ parent وعلى الـ subparser
    معًا، يقوم subparser بإعادة تطبيق قيمته الافتراضية الخاصة به بعد
    انتهاء تحليل الـ subparser، فيمحو القيمة التي مررها المستخدم فعليًا
    قبل اسم الأمر (مثال: `--config x.json scan target` كانت تتجاهل
    x.json وترجع للقيمة الافتراضية بصمت — خطأ خطير لأنه صامت ولا يظهر
    كاستثناء). الحل: تعريف واحد فقط على الـ parser الرئيسي، بحيث ترتيب
    الاستخدام الصحيح والوحيد هو:
        specterscan.py [--config PATH] [--log-level LEVEL] scan <target> ...
    """
    parser = argparse.ArgumentParser(
        prog="specterscan",
        description="SpecterScan — Async SYN-Stealth Port Scanner (Pure Python)",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "--config",
        metavar="PATH",
        default=DEFAULT_CONFIG_PATH,
        help=f"مسار ملف الإعدادات (افتراضي: {DEFAULT_CONFIG_PATH})",
    )
    parser.add_argument(
        "--log-level",
        dest="log_level",
        default=None,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="مستوى تفصيل السجلات (افتراضي: INFO، أو القيمة من config.json)",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="بدء عملية مسح على هدف محدد")
    scan_parser.add_argument("target", help="عنوان IPv4/IPv6، شبكة CIDR، أو hostname (مثال: 192.168.1.1 أو 2001:db8::1 أو 10.0.0.0/24)")
    scan_parser.add_argument("--ports", default=None, help="نطاق المنافذ (افتراضي: 1-1000)")
    scan_parser.add_argument("--rate", type=int, default=None, help="عدد الحزم بالثانية (افتراضي: 500)")
    scan_parser.add_argument("--timeout", type=float, default=None, help="مهلة الانتظار بالثواني لكل هدف (افتراضي: 2.0)")
    scan_parser.add_argument("--decoys", type=int, default=None, help="عدد عناوين IP المزيّفة المرافقة لكل حزمة (افتراضي: 0)")
    scan_parser.add_argument("--output", default=None, choices=["text", "json", "html", "csv"], help="صيغة إخراج النتائج")
    scan_parser.add_argument(
        "--scan-type",
        choices=["syn", "connect", "udp", "fin", "null", "xmas", "ack", "window"],
        default=None,
        help=(
            "نوع الفحص: syn (افتراضي) / connect / udp / "
            "fin / null / xmas (فحوصات تخفي RFC 793) / "
            "ack / window (كشف جدران الحماية)"
        ),
    )
    scan_parser.add_argument("--retries", type=int, default=None, help="عدد إعادة المحاولة عند عدم الرد (افتراضي: 1)")
    scan_parser.add_argument("--workers", type=int, default=None, help="عدد عمليات الفحص المتزامنة (افتراضي: 100)")
    scan_parser.add_argument("--fragment", action="store_true", default=None, help="تجزئة حزم SYN على مستوى IPv4")
    scan_parser.add_argument(
        "--adaptive-rate",
        dest="adaptive_rate",
        action="store_true",
        default=None,
        help="تقليل معدّل الإرسال تلقائيًا عند ارتفاع نسبة فقد الحزم (وزيادته تدريجيًا حين تتحسن)",
    )
    scan_parser.add_argument("--service-detection", action="store_true", default=None, help="تحديد الخدمة للمنافذ المفتوحة")
    scan_parser.add_argument("--banner", action="store_true", default=None, help="محاولة جمع Banner للخدمات المفتوحة")
    scan_parser.add_argument("--resolve", action="store_true", default=None, help="حل IP إلى hostname")
    scan_parser.add_argument("--report", default=None, help="مسار ملف التقرير عند استخدام json/html/csv")
    scan_parser.add_argument("--discover-hosts", action="store_true", default=None, help="اكتشاف الأجهزة النشطة أولًا عند استخدام CIDR")
    scan_parser.add_argument(
        "--plugins-dir",
        dest="plugins_dir",
        default=None,
        help="مسار مجلد الـ plugins (افتراضي: plugins؛ مرّر قيمة فارغة \"\" لتعطيل الـ plugins)",
    )

    return parser


# ---------------------------------------------------------------------------
# تنفيذ subcommand: scan
# ---------------------------------------------------------------------------

def run_scan_command(opts: ScanOptions) -> int:
    """
    ينفّذ subcommand الـ scan فعليًا.

    ملاحظة تطوير: core.scanner يُستورد بشكل كسول (lazy import) داخل try، بحيث:
        - إن كان core/scanner.py غير موجود أصلًا → رسالة واحدة واضحة تشرح ذلك،
          بدل ImportError خام يظهر كأنه خطأ في الأداة نفسها.
        - إن كان موجودًا → يعمل مباشرة بدون أي تعديل على هذا الملف.

    نستورد أيضًا core.scanner.ScannerError هنا (وليس أعلى الملف) للسبب نفسه:
    تفادي أي اعتماد صريح على core.scanner قبل التأكد من وجوده فعليًا.
    """
    try:
        from core.scanner import run_scan, ScannerError  # noqa: WPS433 (استيراد مؤجل مقصود)
    except ImportError:
        log.error(
            "core/scanner.py لم يُبنَ بعد في هذه المرحلة من المشروع — "
            "الأمر 'scan' سيعمل تلقائيًا فور إضافة محرك المسح."
        )
        return EXIT_ERROR

    log.info(
        "بدء المسح: target=%s ports=%s rate=%s timeout=%s decoys=%s output=%s",
        opts.target, opts.ports, opts.rate, opts.timeout, opts.decoys, opts.output,
    )

    try:
        return run_scan(opts)
    except ScannerError as exc:
        # حالة متوقعة ومصمَّم لها صراحة (مثال: Windows لا يدعم raw TCP send) —
        # رسالة واحدة واضحة فقط، بدون Traceback. قبل هذا الإصلاح كانت
        # ScannerError تتسرب لمعالج except Exception العام في main() وتُطبع
        # traceback كامل رغم أنها حالة "متوقعة" وليست خطأ برمجي غير متوقع —
        # وهذا يخالف بند "عدم إظهار Traceback للمستخدم" في متطلبات المشروع.
        log.error(str(exc))
        return EXIT_ERROR


# ---------------------------------------------------------------------------
# نقطة الدخول + المعالج المركزي للأخطاء
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    cli_args = parser.parse_args(argv)

    # نهيئ اللوقر بأبكر وقت ممكن (حتى قبل التحقق من الإعدادات) بمستوى مبدئي،
    # حتى تظهر رسائل الأخطاء التالية بتنسيق موحّد بدل print خام.
    setup_logging(cli_args.log_level or "INFO")

    try:
        config_dict = {}
        # نحاول تحميل config.json فقط إن كان الملف موجودًا فعليًا عند المسار
        # الافتراضي، أو إن حدده المستخدم صراحة عبر --config (وعندها عدم وجوده خطأ حقيقي).
        import os
        user_provided_config = cli_args.config != DEFAULT_CONFIG_PATH
        if user_provided_config or os.path.exists(cli_args.config):
            config_dict = load_config_file(cli_args.config)

        opts = merge_options(cli_args, config_dict)

        # إعادة تهيئة اللوقر بالمستوى النهائي بعد دمج config.json (قد يكون
        # config.json حدد log_level ولم يحدده المستخدم عبر --log-level).
        setup_logging(opts.log_level)

        validate_options(opts)

        if cli_args.command == "scan":
            return run_scan_command(opts)

        parser.error(f"أمر غير معروف: {cli_args.command}")
        return EXIT_ERROR  # لن تُنفَّذ عمليًا (parser.error تنهي البرنامج) لكن توضّح النية للقارئ

    except ConfigError as exc:
        log.error(str(exc))
        return EXIT_ERROR
    except ValidationError as exc:
        log.error(str(exc))
        return EXIT_ERROR
    except PermissionError:
        log.error(
            "صلاحيات غير كافية لتنفيذ العملية. شغّل الأداة كـ root (Linux) "
            "أو Administrator (Windows)."
        )
        return EXIT_ERROR
    except OSError as exc:
        # يغطي فشل الاتصال/الشبكة العام الذي قد يتسرب حتى قبل الدخول لـ core.scanner
        log.error(f"خطأ شبكي غير متوقع: {exc}")
        return EXIT_ERROR
    except KeyboardInterrupt:
        log.warning("تم إيقاف المسح يدويًا (Ctrl+C).")
        return EXIT_ERROR
    except Exception as exc:  # noqa: BLE001 - نقطة الالتقاط الأخيرة عمدًا
        # هذا هو خط الدفاع الأخير: أي استثناء غير متوقع لا يجب أن يُسرّب
        # traceback كامل للمستخدم العادي. يُسجَّل traceback الكامل فقط في
        # DEBUG عبر log.exception، وتظهر للمستخدم رسالة واحدة عامة وواضحة.
        log.exception("حدث خطأ غير متوقع: %s", exc)
        log.error("لمزيد من التفاصيل شغّل الأداة مع --log-level DEBUG")
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())