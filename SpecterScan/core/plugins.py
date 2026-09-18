"""
core/plugins.py
----------------
نظام plugins بسيط لتوسيع كشف الخدمات (core/service_detector.py) دون تعديل
كود المشروع نفسه. أي ملف .py داخل مجلد plugins/ (أو مسار آخر عبر
--plugins-dir) يُعتبر plugin إن عرّف أيًا من:

    PORT_MAP: dict[int, str]
        تخمينات خدمة إضافية حسب رقم المنفذ (مثال: {9999: "my-custom-svc"}).
        لا تُستخدم إلا إن كان المنفذ غير موجود أصلًا في القائمة المدمجة
        (core.service_detector.COMMON_SERVICES) — الـ plugins تُضيف ولا تُلغي.

    PATTERNS: list[tuple[str, str]]
        أنماط regex إضافية على الـ banner، بصيغة (pattern, service_name).
        تُفحص *قبل* الأنماط المدمجة (لتسمح لـ plugin بتخصيص كشف أدق)، لكن
        الأنماط المدمجة تبقى تعمل دائمًا كخط دفاع أخير.

    async def probe(host: str, port: int, timeout: float) -> str | None
        منطق جمع banner مخصص بالكامل (مثلًا بروتوكول غير قياسي). يُجرَّب قبل
        منطق core.service_detector.grab_banner المدمج؛ أول نتيجة غير None
        من أي probe مسجَّل تُستخدم وتوقف باقي المحاولات.

كل الحقول اختيارية — plugin يعرّف PORT_MAP فقط لا يزال plugin صالحًا.

⚠️ ملاحظة أمان مهمة: الـ plugins كود بايثون عادي يُنفَّذ بنفس صلاحيات
SpecterScan نفسها (بدون أي sandbox). لا تُحمّل إلا plugins كتبتها بنفسك أو
تثق بمصدرها تمامًا — هذا نفس مبدأ أي نظام plugins قائم على استيراد كود
(مثل إضافات المتصفح أو IDE)، وليس ميزة أمان بحد ذاته.
"""

from __future__ import annotations

import importlib.util
import sys
from dataclasses import dataclass, field
from pathlib import Path

from utils.logger import get_logger

log = get_logger("core.plugins")

DEFAULT_PLUGINS_DIR = "plugins"


@dataclass
class PluginRegistry:
    port_map: dict[int, str] = field(default_factory=dict)
    patterns: list[tuple[str, str]] = field(default_factory=list)
    probes: list = field(default_factory=list)  # async (host, port, timeout) -> str | None
    loaded: list[str] = field(default_factory=list)  # أسماء ملفات الـ plugins المحمَّلة بنجاح

    def __bool__(self) -> bool:
        return bool(self.port_map or self.patterns or self.probes)


def load_plugins(directory: str | None = DEFAULT_PLUGINS_DIR) -> PluginRegistry:
    """يحمّل كل ملفات .py في directory كـ plugins. عدم وجود المجلد أصلًا ليس
    خطأً (يرجع سجل فارغ ببساطة) — الـ plugins ميزة اختيارية بالكامل."""

    registry = PluginRegistry()

    if not directory:
        return registry

    path = Path(directory)
    if not path.is_dir():
        return registry

    for file in sorted(path.glob("*.py")):
        if file.name.startswith("_"):
            continue
        try:
            _load_one(file, registry)
        except Exception as exc:  # noqa: BLE001 - عزل خطأ plugin واحد عن باقي الـ plugins والفحص نفسه
            log.warning("تعذّر تحميل plugin %s: %s", file.name, exc)

    if registry.loaded:
        log.info(
            "تم تحميل %d plugin: %s",
            len(registry.loaded),
            ", ".join(registry.loaded),
        )

    return registry


def _load_one(file: Path, registry: PluginRegistry) -> None:
    module_name = f"specterscan_plugin_{file.stem}"

    spec = importlib.util.spec_from_file_location(module_name, file)
    if spec is None or spec.loader is None:
        raise ImportError(f"تعذّر بناء module spec من {file}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)

    port_map = getattr(module, "PORT_MAP", None)
    if isinstance(port_map, dict):
        for port, name in port_map.items():
            registry.port_map.setdefault(int(port), str(name))

    patterns = getattr(module, "PATTERNS", None)
    if isinstance(patterns, list):
        registry.patterns.extend((str(p), str(s)) for p, s in patterns)

    probe = getattr(module, "probe", None)
    if callable(probe):
        registry.probes.append(probe)

    registry.loaded.append(file.name)
