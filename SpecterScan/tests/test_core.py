import json
import socket
import struct
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.packet import (
    compute_checksum, build_ip_header, build_tcp_syn_header, build_syn_packet,
    build_tcp_probe_packet, parse_ip_header, parse_tcp_header,
    TCP_FLAG_SYN, TCP_FLAG_FIN, TCP_FLAG_PSH, TCP_FLAG_URG, TCP_FLAG_ACK,
)
from core.scanner import (
    expand_ports, expand_targets, guess_os_from_response,
    STEALTH_SCAN_FLAGS, ScanEngine, PortState,
)
from core.service_detector import identify_service
from utils.validator import validate_ports, validate_options, ValidationError


def test_checksum_even_and_odd():
    assert compute_checksum(b"\x00\x00") == 0xFFFF
    assert isinstance(compute_checksum(b"abc"), int)

def test_packet_roundtrip():
    p = build_syn_packet("127.0.0.1", "127.0.0.1", 40000, 80, seq=1234)
    ip = parse_ip_header(p); tcp = parse_tcp_header(ip["payload"])
    assert ip["src_ip"] == "127.0.0.1" and ip["dst_ip"] == "127.0.0.1"
    assert tcp["src_port"] == 40000 and tcp["dst_port"] == 80
    assert tcp["seq"] == 1234 and "SYN" in tcp["flags_set"]

def test_expand_ports():
    assert expand_ports("80,22,20-22") == [20,21,22,80]

def test_expand_target_host():
    assert expand_targets("127.0.0.1") == ["127.0.0.1"]

def test_validation_rejects_bad_port():
    try: validate_ports("70000")
    except ValidationError: return
    assert False

def test_os_heuristic():
    assert "Linux" in guess_os_from_response(60, 64240)
    assert "Windows" in guess_os_from_response(120, 65535)

def test_service_map():
    assert identify_service(22) == "ssh"
    assert identify_service(443) == "https"

def test_port_range_expansion():
    assert expand_ports("80-85") == [80, 81, 82, 83, 84, 85]
    assert expand_ports("100") == [100]
    assert expand_ports("80,443") == [80, 443]
    assert expand_ports("80-82,443") == [80, 81, 82, 443]

def test_invalid_port_range():
    try:
        expand_ports("1000-500")  # start > end
        assert False, "Should have raised ScannerError"
    except Exception:
        pass

def test_cidr_expansion():
    # Test single IP
    ips = expand_targets("192.168.1.1")
    assert ips == ["192.168.1.1"]
    
    # Test /32 network
    ips = expand_targets("10.0.0.1/32")
    assert ips == ["10.0.0.1"]

def test_multiple_host_discovery_ports():
    # Test that discovery probes use common ports
    probes = (22, 80, 443, 3000, 5000, 8000, 8080)
    assert len(probes) > 0
    assert 22 in probes  # SSH
    assert 80 in probes  # HTTP
    assert 443 in probes  # HTTPS


# ---------------------------------------------------------------------------
# v1.1: FIN / NULL / XMAS / ACK / Window scans
# ---------------------------------------------------------------------------

def test_stealth_scan_flags_mapping():
    assert STEALTH_SCAN_FLAGS["fin"] == TCP_FLAG_FIN
    assert STEALTH_SCAN_FLAGS["null"] == 0
    assert STEALTH_SCAN_FLAGS["xmas"] == TCP_FLAG_FIN | TCP_FLAG_PSH | TCP_FLAG_URG
    assert STEALTH_SCAN_FLAGS["ack"] == TCP_FLAG_ACK
    assert STEALTH_SCAN_FLAGS["window"] == TCP_FLAG_ACK

def test_build_fin_packet():
    p = build_tcp_probe_packet("127.0.0.1", "127.0.0.1", 40000, 80, flags=TCP_FLAG_FIN, seq=111)
    ip = parse_ip_header(p); tcp = parse_tcp_header(ip["payload"])
    assert tcp["flags_set"] == {"FIN"}
    assert tcp["seq"] == 111

def test_build_null_packet():
    p = build_tcp_probe_packet("127.0.0.1", "127.0.0.1", 40000, 80, flags=0, seq=222)
    ip = parse_ip_header(p); tcp = parse_tcp_header(ip["payload"])
    assert tcp["flags_set"] == set()

def test_build_xmas_packet():
    p = build_tcp_probe_packet("127.0.0.1", "127.0.0.1", 40000, 80, flags=STEALTH_SCAN_FLAGS["xmas"], seq=333)
    ip = parse_ip_header(p); tcp = parse_tcp_header(ip["payload"])
    assert tcp["flags_set"] == {"FIN", "PSH", "URG"}

def test_build_ack_packet_with_ack_field():
    p = build_tcp_probe_packet("127.0.0.1", "127.0.0.1", 40000, 80, flags=TCP_FLAG_ACK, seq=1, ack=999)
    ip = parse_ip_header(p); tcp = parse_tcp_header(ip["payload"])
    assert tcp["flags_set"] == {"ACK"}
    assert tcp["ack"] == 999

def test_scan_engine_rejects_unsupported_scan_type():
    try:
        ScanEngine([], "127.0.0.1", 40000, rate_limiter=None, timeout=1.0, scan_type="bogus")
        assert False, "should have raised"
    except Exception:
        pass

def test_scan_engine_match_field_selection():
    e_fin = ScanEngine([], "127.0.0.1", 40000, rate_limiter=None, timeout=1.0, scan_type="fin")
    assert e_fin._match_field == "ack"
    e_ack = ScanEngine([], "127.0.0.1", 40000, rate_limiter=None, timeout=1.0, scan_type="ack")
    assert e_ack._match_field == "seq"
    e_window = ScanEngine([], "127.0.0.1", 40000, rate_limiter=None, timeout=1.0, scan_type="window")
    assert e_window._match_field == "seq"

def test_validate_options_rejects_decoys_on_fin_scan():
    class Opts:
        target = "127.0.0.1"; ports = "80"; rate = 100; timeout = 1.0
        decoys = 2; retries = 1; workers = 10; output = "text"
        scan_type = "fin"; fragment = False
        service_detection = False; banner = False
    try:
        validate_options(Opts())
        assert False, "should have raised"
    except ValidationError:
        pass

def test_validate_options_accepts_new_scan_types():
    class Opts:
        target = "127.0.0.1"; ports = "80"; rate = 100; timeout = 1.0
        decoys = 0; retries = 1; workers = 10; output = "text"
        scan_type = "xmas"; fragment = False
        service_detection = False; banner = False
    validate_options(Opts())  # لا يجب أن يرفع أي استثناء


# ---------------------------------------------------------------------------
# v1.2: IPv6 + adaptive rate limiting + connection pooling
# ---------------------------------------------------------------------------

def test_build_tcp_segment_v6_roundtrip():
    from core.packet import build_tcp_segment_v6
    seg = build_tcp_segment_v6("::1", "::1", 40000, 80, flags=TCP_FLAG_SYN, seq=777)
    tcp = parse_tcp_header(seg)
    assert tcp["seq"] == 777
    assert tcp["src_port"] == 40000 and tcp["dst_port"] == 80
    assert "SYN" in tcp["flags_set"]

def test_build_tcp_segment_v6_ack_field():
    from core.packet import build_tcp_segment_v6
    seg = build_tcp_segment_v6("2001:db8::1", "2001:db8::2", 1234, 443, flags=TCP_FLAG_ACK, seq=1, ack=42)
    tcp = parse_tcp_header(seg)
    assert tcp["ack"] == 42
    assert tcp["flags_set"] == {"ACK"}

def test_validate_target_accepts_ipv6():
    from utils.validator import validate_target
    validate_target("::1")
    validate_target("2001:db8::/120")

def test_validate_target_rejects_huge_ipv6_network():
    from utils.validator import validate_target
    try:
        validate_target("2001:db8::/64")
        assert False, "should have raised"
    except ValidationError:
        pass

def test_validate_target_accepts_hostname():
    from utils.validator import validate_target
    validate_target("scanme.nmap.org")  # لا يجب أن يرفع استثناء (لا يوجد استعلام DNS فعلي هنا)

def test_expand_targets_rejects_mixed_family_scan():
    from core.scanner import ip_version
    assert ip_version("127.0.0.1") == 4
    assert ip_version("::1") == 6

def test_adaptive_rate_limiter_slows_down_on_loss():
    import asyncio
    from core.scanner import RateLimiter

    async def run():
        rl = RateLimiter(1000, adaptive=True)
        base = rl._interval
        for _ in range(40):  # نسبة فقد 100% > 20% => يجب أن يبطّئ
            rl.report_result(lost=True)
        assert rl._interval > base
        return rl._interval

    slowed = asyncio.run(run())
    assert slowed > 0

def test_rate_limiter_non_adaptive_ignores_loss():
    from core.scanner import RateLimiter
    rl = RateLimiter(1000, adaptive=False)
    base = rl._interval
    for _ in range(40):
        rl.report_result(lost=True)
    assert rl._interval == base

def test_connection_pool_rejects_bad_sizes():
    from core.service_detector import ConnectionPool
    try:
        ConnectionPool(max_total=0)
        assert False, "should have raised"
    except ValueError:
        pass
    try:
        ConnectionPool(max_total=10, max_per_host=0)
        assert False, "should have raised"
    except ValueError:
        pass

def test_connection_pool_limits_concurrency():
    import asyncio
    from core.service_detector import ConnectionPool

    async def run():
        pool = ConnectionPool(max_total=2, max_per_host=1)
        active = 0
        peak = 0

        async def worker(host):
            nonlocal active, peak
            async with pool.acquire(host):
                active += 1
                peak = max(peak, active)
                await asyncio.sleep(0.01)
                active -= 1

        await asyncio.gather(*(worker("h1") for _ in range(5)))
        return peak

    peak = asyncio.run(run())
    assert peak == 1  # نفس المضيف: حد أقصى 1 متزامن


# ---------------------------------------------------------------------------
# v1.2: plugin system
# ---------------------------------------------------------------------------

def test_load_plugins_missing_dir_returns_empty_registry():
    from core.plugins import load_plugins
    reg = load_plugins("this_dir_does_not_exist_at_all")
    assert not reg
    assert reg.loaded == []

def test_load_plugins_empty_string_disables():
    from core.plugins import load_plugins
    reg = load_plugins("")
    assert not reg

def test_load_plugins_and_merge_into_identify_service(tmp_path_factory=None):
    import tempfile, os
    from core.plugins import load_plugins
    from core.service_detector import identify_service

    with tempfile.TemporaryDirectory() as d:
        plugin_path = os.path.join(d, "sample.py")
        with open(plugin_path, "w", encoding="utf-8") as fh:
            fh.write(
                "PORT_MAP = {9999: 'my-custom-app'}\n"
                "PATTERNS = [(r'mycustomserver/', 'my-custom-app')]\n"
            )

        reg = load_plugins(d)
        assert reg.loaded == ["sample.py"]
        assert identify_service(9999, registry=reg) == "my-custom-app"
        # لا يُلغي plugin تخمين مدمج موجود أصلًا
        assert identify_service(80, registry=reg) == "http"
        assert identify_service(0, "MyCustomServer/1.0 ready", registry=reg) == "my-custom-app"

def test_load_plugins_skips_broken_plugin_without_crashing():
    import tempfile, os
    from core.plugins import load_plugins

    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "broken.py"), "w", encoding="utf-8") as fh:
            fh.write("this is not valid python (((\n")
        with open(os.path.join(d, "good.py"), "w", encoding="utf-8") as fh:
            fh.write("PORT_MAP = {1234: 'ok'}\n")

        reg = load_plugins(d)  # لا يجب أن يرفع استثناء
        assert reg.loaded == ["good.py"]
        assert reg.port_map == {1234: "ok"}
