"""
مثال plugin — انسخه إلى plugins/ (مجلد واحد للأعلى) لتفعيله فعليًا.
SpecterScan تحمّل تلقائيًا كل ملف .py مباشرة داخل plugins/ (وليس داخل
plugins/examples/، لذا هذا الملف لا يعمل من مكانه الحالي — وهذا مقصود،
حتى لا تُفعَّل الأمثلة تلقائيًا لمجرد وجودها في المستودع).

يوضّح هذا المثال الحقول الثلاثة الاختيارية التي يفهمها core/plugins.py.
"""

# 1) تخمينات منفذ إضافية — تُستخدم فقط إن كان المنفذ غير معروف أصلًا
#    في core.service_detector.COMMON_SERVICES.
PORT_MAP = {
    9999: "my-custom-app",
    27017: "mongodb",
}

# 2) أنماط regex إضافية على الـ banner — تُفحص قبل الأنماط المدمجة.
PATTERNS = [
    (r"mycustomserver/", "my-custom-app"),
]


# 3) منطق جمع banner مخصص بالكامل (اختياري) — مفيد لبروتوكول غير قياسي
#    لا يكفي معه إرسال HEAD HTTP بسيط أو انتظار greeting تلقائي.
async def probe(host: str, port: int, timeout: float) -> str | None:
    import asyncio

    if port != 9999:
        return None  # لا شيء مخصص لهذا المنفذ — دع SpecterScan يستخدم المنطق الافتراضي

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.write(b"PING\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(128), timeout=timeout)
        writer.close()
        return data.decode("utf-8", errors="replace").strip() or None
    except (OSError, asyncio.TimeoutError):
        return None
