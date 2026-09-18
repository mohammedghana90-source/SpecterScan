"""
utils/logger.py
----------------
نظام سجلات (logging) احترافي وملوّن — Pure Python بالكامل.

لا نستخدم colorama ولا rich (ممنوعتان حسب قيد Pure Python)، بل ANSI escape
codes مباشرة، مع تعطيل تلقائي للألوان إن لم تكن المخرجات طرفية تفاعلية
(مثلًا عند إعادة التوجيه لملف: specterscan.py scan ... > out.txt).

الاستخدام من أي وحدة أخرى في المشروع:
    from utils.logger import get_logger
    log = get_logger(__name__)
    log.info("بدء المسح على %s", target)
"""

from __future__ import annotations

import logging
import sys

# ---------------------------------------------------------------------------
# أكواد ANSI للألوان
# ---------------------------------------------------------------------------

class _Ansi:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    GREY = "\033[90m"
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD_RED = "\033[1m\033[91m"


_LEVEL_COLORS = {
    logging.DEBUG: _Ansi.GREY,
    logging.INFO: _Ansi.GREEN,
    logging.WARNING: _Ansi.YELLOW,
    logging.ERROR: _Ansi.RED,
    logging.CRITICAL: _Ansi.BOLD_RED,
}


def _supports_color(stream) -> bool:
    """
    يحدد إن كان يجدر طباعة ألوان على هذا الـ stream.

    الشرط: أن يكون stream متصلًا فعليًا بطرفية تفاعلية (isatty). هذا يمنع
    تلقائيًا تسريب أكواد ANSI الخام إلى ملفات الإخراج أو الأنابيب (pipes)،
    وهو سلوك قياسي متوقع من أي أداة CLI احترافية (نفس ما تفعله git, ls
    الحديثة، إلخ).
    """
    return hasattr(stream, "isatty") and stream.isatty()


class ColorFormatter(logging.Formatter):
    """
    Formatter مخصص يضيف لونًا لكامل السطر حسب مستوى الرسالة (levelno)،
    ويسقط الألوان تلقائيًا إن كانت المخرجات غير تفاعلية.

    شكل السطر:
        [HH:MM:SS] LEVEL    اسم_الوحدة: الرسالة
    """

    _BASE_FORMAT = "[%(asctime)s] %(levelname)-8s %(name)s: %(message)s"
    _DATE_FORMAT = "%H:%M:%S"

    def __init__(self, use_color: bool):
        super().__init__(fmt=self._BASE_FORMAT, datefmt=self._DATE_FORMAT)
        self._use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        formatted = super().format(record)
        if not self._use_color:
            return formatted
        color = _LEVEL_COLORS.get(record.levelno, "")
        return f"{color}{formatted}{_Ansi.RESET}"


# ---------------------------------------------------------------------------
# إعداد اللوقر على مستوى التطبيق (يُستدعى مرة واحدة من specterscan.py)
# ---------------------------------------------------------------------------

_LEVEL_NAMES: dict[str, int] = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}

_ROOT_LOGGER_NAME = "specterscan"
_configured = False  # يمنع إضافة handlers مكررة لو استُدعيت setup_logging أكثر من مرة


def setup_logging(level_name: str = "INFO") -> logging.Logger:
    """
    يهيئ اللوقر الجذري للمشروع مرة واحدة عند بدء التشغيل، حسب قيمة --log-level.

    المعاملات:
        level_name: أحد "DEBUG" | "INFO" | "WARNING" | "ERROR" (غير حساس لحالة الأحرف).

    يرجع:
        كائن Logger جاهز، لكن الاستخدام المعتاد في باقي الوحدات هو عبر
        get_logger(__name__) وليس هذا الكائن مباشرة.

    ملاحظة معالجة أخطاء: لو مُرِّرت قيمة log-level غير صحيحة، لا نرمي استثناء
    يوقف البرنامج بغموض — بل نُرجع تحذيرًا واحدًا واضحًا ونستخدم INFO كافتراضي
    آمن (اتساقًا مع مبدأ "رسالة خطأ واحدة واضحة" في متطلبات المشروع).
    """
    global _configured

    normalized = level_name.strip().upper()
    # نبحث في قاموس صريح مكتوب يدويًا (_LEVEL_NAMES: dict[str, int]) بدل
    # getattr(logging, normalized, None) القديمة. السبب ليس فقط أسلوبيًا:
    # getattr على module يرجع النوع Any من منظور محلل الأنواع الساكن، حتى
    # لو مُرِّر default=None، فلا يقدر المحلل يميّز لاحقًا بين "قيمة عددية
    # صحيحة" و"لا شيء" بثقة — ومن هنا جاء تحذير "Expected int, got Any|None".
    # القاموس المكتوب صراحة بـ dict[str, int] يعطي .get() نوعًا دقيقًا
    # (int | None)، فيقدر المحلل يتتبع أن numeric_level أصبح int فعليًا
    # بعد أي فرع يستبعد None (بما في ذلك الـ return المبكر أدناه).
    numeric_level = _LEVEL_NAMES.get(normalized)

    root = logging.getLogger(_ROOT_LOGGER_NAME)

    if numeric_level is None:
        numeric_level = logging.INFO
        _apply_handler(root, numeric_level)
        root.warning(
            "قيمة --log-level غير معروفة: %r — تم استخدام INFO كافتراضي.",
            level_name,
        )
        _configured = True
        return root

    # _apply_handler تُفرغ أي handlers سابقة قبل الإضافة (انظر تعليقها أدناه)،
    # لذا استدعاؤها بأمان في كل مرة — أول استدعاء أو أي استدعاء متكرر لاحق —
    # ينتج دائمًا حالة نظيفة بـ handler واحد بالضبط، بلا حاجة لتفريع منطق يدوي.
    _apply_handler(root, numeric_level)
    _configured = True

    return root


def _apply_handler(root: logging.Logger, level: int) -> None:
    """يربط handler واحد فقط بمخرجات stderr (تقليدًا لأدوات CLI: stdout للنتائج، stderr للسجلات).

    نُفرغ أي handlers سابقة قبل الإضافة (root.handlers.clear()) لضمان أن الدالة
    idempotent: حتى لو استُدعيت setup_logging() أكثر من مرة بالغلط (مثلًا من
    كود اختبار، أو استيراد مزدوج للوحدة)، لن تتكرر الرسائل على الشاشة مرتين.
    """
    root.handlers.clear()

    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(ColorFormatter(use_color=_supports_color(sys.stderr)))
    handler.setLevel(level)

    root.setLevel(level)
    root.addHandler(handler)
    root.propagate = False  # يمنع تكرار الطباعة عبر اللوقر الجذري الافتراضي لبايثون


def get_logger(module_name: str) -> logging.Logger:
    """
    يرجع logger فرعي تابع للوقر الجذري للمشروع، بحيث تظهر رسائل كل وحدة
    باسمها (specterscan.core.scanner مثلًا) لتسهيل التتبع أثناء --log-level DEBUG.

    يجب استدعاء setup_logging() مرة واحدة من specterscan.py قبل استخدام هذه
    الدالة في أي وحدة أخرى؛ إن لم يُستدعَ، تُستخدم إعدادات Python الافتراضية
    (لا تعطّل التطبيق، لكن بدون ألوان أو تنسيق مخصص).
    """
    return logging.getLogger(f"{_ROOT_LOGGER_NAME}.{module_name}")