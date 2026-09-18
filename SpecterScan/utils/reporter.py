from __future__ import annotations
import csv
import html
import io
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path


def _result_to_dict(result):
    data = asdict(result)
    data["state"] = result.state.value
    return data

def build_payload(results, *, target=None, scan_type=None, duration=None, stats=None):
    counts = {}
    for r in results:
        counts[r.state.value] = counts.get(r.state.value, 0) + 1
    return {
        "tool": "SpecterScan",
        "version": "1.2.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "scan_type": scan_type,
        "duration_seconds": round(duration, 3) if duration is not None else None,
        "statistics": {**(stats or {}), "total_results": len(results), "states": counts},
        "results": [_result_to_dict(r) for r in results],
    }

def generate_json_report(results, **meta):
    return json.dumps(build_payload(results, **meta), ensure_ascii=False, indent=2)

def write_json_report(results, path, **meta):
    Path(path).write_text(generate_json_report(results, **meta), encoding="utf-8")

def generate_csv_report(results):
    fields = ["host","hostname","port","protocol","state","latency_ms","ttl","window","os_guess","service","banner","attempts"]
    out = io.StringIO(); writer = csv.DictWriter(out, fieldnames=fields); writer.writeheader()
    for r in results:
        d = _result_to_dict(r); writer.writerow({k: d.get(k) for k in fields})
    return out.getvalue()

def write_csv_report(results, path):
    Path(path).write_text(generate_csv_report(results), encoding="utf-8", newline="")

def generate_html_report(results, *, target=None, scan_type=None, duration=None, stats=None, title="SpecterScan Report"):
    payload = build_payload(results, target=target, scan_type=scan_type, duration=duration, stats=stats)
    rows=[]
    for r in results:
        d=_result_to_dict(r)
        rows.append("<tr>" + "".join(f"<td>{html.escape(str(d.get(k) if d.get(k) is not None else '-'))}</td>" for k in ["host","hostname","port","protocol","state","latency_ms","service","banner","os_guess","attempts"]) + "</tr>")
    meta=f"Target: {html.escape(str(target or '-'))} | Scan: {html.escape(str(scan_type or '-'))} | Duration: {html.escape(str(payload['duration_seconds'] or '-'))}s"
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{html.escape(title)}</title><style>body{{font-family:Segoe UI,Arial,sans-serif;margin:32px;background:#111827;color:#e5e7eb}}h1{{margin-bottom:4px}}.meta{{color:#9ca3af}}table{{width:100%;border-collapse:collapse;margin-top:24px;background:#1f2937}}th,td{{padding:9px;border-bottom:1px solid #374151;text-align:left;vertical-align:top}}th{{background:#374151}}.open{{font-weight:700}}</style></head><body><h1>{html.escape(title)}</h1><p class="meta">{meta}</p><table><thead><tr><th>Host</th><th>Hostname</th><th>Port</th><th>Protocol</th><th>State</th><th>Latency</th><th>Service</th><th>Banner</th><th>OS</th><th>Attempts</th></tr></thead><tbody>{''.join(rows) or '<tr><td colspan="10">No results</td></tr>'}</tbody></table></body></html>'''

def write_html_report(results, path, **meta):
    Path(path).write_text(generate_html_report(results, **meta), encoding="utf-8")

def emit_report(results, output_format, *, target=None, scan_type=None, duration=None, stats=None, path=None):
    meta=dict(target=target, scan_type=scan_type, duration=duration, stats=stats)
    if output_format == "text":
        _print_text(results, target, scan_type, duration, stats); return
    if output_format == "json":
        text=generate_json_report(results, **meta)
        if path: write_json_report(results,path,**meta); print(f"JSON report: {path}")
        else: print(text)
    elif output_format == "html":
        path=path or "specterscan_report.html"; write_html_report(results,path,**meta); print(f"HTML report: {path}")
    elif output_format == "csv":
        path=path or "specterscan_report.csv"; write_csv_report(results,path); print(f"CSV report: {path}")

# الحالات "المهمة" التي تُطبع في الملخص النصي تختلف حسب نوع الفحص:
# - الفحوصات الاعتيادية (syn/connect/udp/fin/null/xmas): open أو open|filtered.
# - ACK scan: هدفه كشف الحجب فقط، فالنتيجة المفيدة هي unfiltered.
# - Window scan: يميّز open عن closed (كلاهما "غير محجوب")، فالنتيجتان مفيدتان.
_INTERESTING_STATES = {
    "ack": {"unfiltered"},
    "window": {"open", "closed"},
}
_DEFAULT_INTERESTING_STATES = {"open", "open|filtered"}


def _print_text(results, target, scan_type, duration, stats):
    print("\n=== SpecterScan ===")
    print(f"Target: {target} | Scan: {scan_type} | Duration: {duration:.2f}s")
    print(
        f"{'HOST':<16} {'PORT':<7} {'PROTO':<6} {'STATE':<14} "
        f"{'SERVICE':<14} {'LATENCY':<10} OS"
    )
    print("-" * 100)

    interesting = _INTERESTING_STATES.get(scan_type, _DEFAULT_INTERESTING_STATES)

    open_results = [
        r for r in results
        if r.state.value in interesting
    ]

    for r in open_results:
        print(
            f"{r.host:<16} "
            f"{r.port:<7} "
            f"{r.protocol:<6} "
            f"{r.state.value:<14} "
            f"{(r.service or '-'): <14} "
            f"{(str(r.latency_ms) + 'ms') if r.latency_ms is not None else '-':<10} "
            f"{r.os_guess or '-'}"
        )

        if r.banner:
            print("  Banner:")
            # عرض الـ Banner بشكل منظم، مع كسر الأسطر الطويلة
            banner_lines = r.banner.replace("\\n", "\n").splitlines()

            for line in banner_lines:
                line = line.strip()
                if line:
                    print(f"    {line}")

    if not open_results:
        if scan_type == "ack":
            print("No unfiltered ports found in the selected range.")
        else:
            print("No open ports found in the selected range.")

    counts = {
        s: sum(1 for r in results if r.state.value == s)
        for s in {r.state.value for r in results}
    }
    print("Statistics:", counts)
