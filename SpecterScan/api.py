#!/usr/bin/env python3
"""
api.py
------
REST API اختياري فوق core.scanner، بمكتبة قياسية بحتة (http.server) — بدون
أي إطار عمل خارجي (Flask/FastAPI/...)، اتساقًا مع فلسفة المشروع الكاملة
(pure stdlib, لا تبعيات خارجية).

⚠️ تحذير أمان مهم قبل أي استخدام:
هذا API لا يطلب أي مصادقة (authentication) افتراضيًا، ويُشغِّل فحوصات شبكة
فعلية (قد تتطلب صلاحيات root لأنواع syn/fin/null/xmas/ack/window). لا تُشغّله
مكشوفًا على شبكة عامة أو غير موثوقة إطلاقًا — أي طرف يصل إلى هذا المنفذ
يستطيع تشغيل فحوصات شبكة نيابة عن الخادم. الاستخدام المقصود: محليًا
(127.0.0.1) أو خلف طبقة مصادقة/شبكة خاصة تديرها أنت بنفسك (reverse proxy،
VPN، أو mTLS) — هذا الملف لا يوفر أيًا من ذلك بنفسه عمدًا (خارج نطاق
"أداة مسح تعليمية pure-Python" التي يهدف إليها المشروع).

يستخدم نفس منطق التحقق (utils/validator.py) والتنفيذ (core.scanner.execute_scan)
المستخدَمَين من CLI حرفيًا — لا منطق فحص مكرر هنا، فقط طبقة HTTP/JSON رقيقة.

التشغيل:
    python3 api.py --host 127.0.0.1 --port 8787

نقاط النهاية (Endpoints):
    GET  /health                  -> {"status": "ok", "version": "..."}
    POST /scan                    -> يشغّل فحصًا ويرجع النتائج كـ JSON

مثال طلب POST /scan (كل الحقول اختيارية عدا target):
    {
        "target": "127.0.0.1",
        "ports": "1-1000",
        "scan_type": "connect",
        "timeout": 2.0,
        "rate": 500,
        "retries": 1,
        "workers": 100,
        "service_detection": true,
        "banner": false,
        "resolve": false
    }
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import traceback
from dataclasses import fields
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from specterscan import ScanOptions, __version__
from utils.logger import get_logger, setup_logging
from utils.validator import ValidationError, validate_options

log = get_logger("api")

# أقصى حجم لجسم الطلب (بايت) — حماية بسيطة من طلبات ضخمة عشوائية/خبيثة قبل
# حتى محاولة تحليلها كـ JSON.
MAX_BODY_BYTES = 1_000_000

# حقول ScanOptions المسموح ضبطها من جسم طلب JSON مباشرة (استثناء target
# لأنه إلزامي ويُعامَل بشكل منفصل، وextra لأنه داخلي بحت).
_ALLOWED_FIELDS = {
    f.name for f in fields(ScanOptions) if f.name not in ("target", "extra")
}


class _ScanRequestHandler(BaseHTTPRequestHandler):
    server_version = f"SpecterScan-API/{__version__}"

    def log_message(self, format, *args):  # noqa: A002 - توقيع BaseHTTPRequestHandler
        log.info("%s - %s", self.address_string(), format % args)

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802 - اسم مفروض من BaseHTTPRequestHandler
        if self.path == "/health":
            self._send_json(200, {"status": "ok", "version": __version__})
            return

        self._send_json(404, {"error": f"مسار غير معروف: {self.path}"})

    def do_POST(self):  # noqa: N802
        if self.path != "/scan":
            self._send_json(404, {"error": f"مسار غير معروف: {self.path}"})
            return

        length = int(self.headers.get("Content-Length", 0) or 0)
        if length <= 0:
            self._send_json(400, {"error": "جسم الطلب فارغ — يلزم JSON فيه على الأقل الحقل target"})
            return
        if length > MAX_BODY_BYTES:
            self._send_json(413, {"error": f"جسم الطلب كبير جدًا (> {MAX_BODY_BYTES} بايت)"})
            return

        raw = self.rfile.read(length)

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            self._send_json(400, {"error": f"JSON غير صالح: {exc}"})
            return

        if not isinstance(payload, dict) or "target" not in payload:
            self._send_json(400, {"error": "الحقل target إلزامي في جسم الطلب"})
            return

        unknown = set(payload) - _ALLOWED_FIELDS - {"target"}
        if unknown:
            self._send_json(400, {"error": f"حقول غير معروفة: {', '.join(sorted(unknown))}"})
            return

        try:
            opts = ScanOptions(
                target=str(payload["target"]),
                **{k: v for k, v in payload.items() if k in _ALLOWED_FIELDS},
            )
        except TypeError as exc:
            self._send_json(400, {"error": f"خيارات فحص غير صالحة: {exc}"})
            return

        try:
            validate_options(opts)
        except ValidationError as exc:
            self._send_json(422, {"error": str(exc)})
            return

        try:
            from core.scanner import execute_scan, ScannerError

            outcome = execute_scan(opts)

        except ScannerError as exc:
            self._send_json(422, {"error": str(exc)})
            return
        except PermissionError:
            self._send_json(
                403,
                {"error": "صلاحيات غير كافية على الخادم لتنفيذ هذا النوع من الفحص (يحتاج root لـ raw sockets)"},
            )
            return
        except Exception as exc:  # noqa: BLE001 - لا نسرّب traceback للعميل أبدًا
            log.exception("خطأ غير متوقع أثناء تنفيذ فحص عبر API: %s", exc)
            self._send_json(500, {"error": "خطأ داخلي غير متوقع — راجع سجلات الخادم"})
            return

        from utils.reporter import build_payload

        response = build_payload(
            outcome["results"],
            target=outcome["target"],
            scan_type=outcome["scan_type"],
            duration=outcome["duration"],
            stats=outcome["stats"],
        )
        self._send_json(200, response)


def serve(host: str = "127.0.0.1", port: int = 8787) -> None:
    server = ThreadingHTTPServer((host, port), _ScanRequestHandler)
    log.info("SpecterScan API يعمل على http://%s:%d (Ctrl+C للإيقاف)", host, port)
    log.warning(
        "لا يوجد مصادقة على هذا الخادم — لا تُعرّضه لشبكة غير موثوقة. "
        "راجع التحذير في أعلى api.py."
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("تم الإيقاف يدويًا (Ctrl+C).")
    finally:
        server.server_close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="specterscan-api", description="SpecterScan REST API (stdlib only)")
    parser.add_argument("--host", default="127.0.0.1", help="عنوان الربط (افتراضي: 127.0.0.1 — محليًا فقط)")
    parser.add_argument("--port", type=int, default=8787, help="المنفذ (افتراضي: 8787)")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args(argv)

    setup_logging(args.log_level)
    serve(args.host, args.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
