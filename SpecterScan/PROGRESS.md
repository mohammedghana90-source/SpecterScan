# SpecterScan Development Progress

## Current Version: v1.2.0 — Feature-complete against original roadmap

All items from the original v1.1+ roadmap (Priority 1, 2's IPv6 item, and
the Integration items REST API/plugin system) are now implemented. See
[CHANGELOG.md](CHANGELOG.md) for the full per-version history — this file
tracks status and open follow-ups going forward.

---

## ✅ Completed Features

### Core Scanning
- [x] TCP SYN Stealth Scan with raw sockets (IPv4 + IPv6)
- [x] TCP Connect Scan (no raw sockets required)
- [x] UDP Probe Scanning
- [x] FIN / NULL / XMAS scans (RFC 793 quirk scans)
- [x] ACK scan (firewall/filtering detection — `unfiltered`/`filtered`)
- [x] Window scan (ACK probe + RST window-size heuristic for open/closed)
- [x] IPv4 + IPv6 TCP/IP header construction and parsing (pure Python,
      `struct`/`socket` only)
- [x] Packet parsing and validation
- [x] Checksum calculation (RFC 791/793/8200)

### Concurrency & Performance
- [x] asyncio-based concurrent scanning
- [x] Semaphore-based worker pool
- [x] Rate limiting (packets per second)
- [x] **Adaptive rate limiting** — backs off automatically under packet
      loss, recovers gradually (`--adaptive-rate`)
- [x] Connection pooling for service detection (global + per-host caps)
- [x] Retry mechanism with configurable attempts
- [x] Timeout handling

### Evasion & Advanced Features
- [x] Decoy IP addresses (SYN scan, IPv4 only)
- [x] IP fragmentation support (SYN scan, IPv4 only)
- [x] Randomized scan order
- [x] TTL/window-based OS fingerprinting (heuristic)

### Service & Host Enumeration
- [x] Service identification (port-based + banner-based)
- [x] Banner grabbing for common protocols
- [x] Reverse DNS resolution
- [x] Host discovery from CIDR networks
- [x] CIDR/hostname/IPv4/IPv6 target expansion (with sane size caps —
      see Limitations)
- [x] **Plugin system** for custom service detection (`core/plugins.py`,
      `--plugins-dir`) — port-map extras, banner regex patterns, and fully
      custom async probes, all loaded from user-supplied `.py` files with
      no core code changes

### Reporting & Output
- [x] JSON report generation
- [x] HTML report generation (styled tables)
- [x] CSV report export
- [x] Text/console output (per-scan-type "interesting states" — e.g. ACK
      scan summarizes `unfiltered`, not `open`)
- [x] Scan statistics (packets sent/received/lost)

### Integration
- [x] **REST API** (`api.py`) — stdlib-only `http.server`, same validated
      pipeline as the CLI via `core.scanner.execute_scan()`. See
      `docs/API.md`.
- [ ] Database backend for results — not planned; out of scope for a
      dependency-free tool (SQLite could be added later without breaking
      the no-deps rule, if there's real demand)

### Infrastructure
- [x] Professional CLI with argparse
- [x] Configuration file support (config.json)
- [x] Structured logging with ANSI colors
- [x] Input validation (targets — IPv4/IPv6/hostname/CIDR —, ports, options)
- [x] Centralized error handling (never leaks a raw traceback to the user)
- [x] Pure Python (no external dependencies) — including the REST API

### Testing
- [x] Unit tests for core functions (packet construction/parsing for both
      IPv4 and IPv6, checksum, target/port expansion)
- [x] Packet roundtrip verification (v4 and v6)
- [x] Validator rules for every scan type and IP family
- [x] Rate limiter adaptive-behavior tests
- [x] Connection pool concurrency-limit tests
- [x] Plugin loading tests (missing dir, disabled, broken plugin isolation,
      successful merge into `identify_service`)
- [x] 34/34 tests passing with zero external test dependencies required

---

## 📋 Known Issues & Limitations

- **OS Detection**: heuristic only (TTL/window), not definitive.
- **UDP Ambiguity**: no-response UDP ports reported as `open|filtered`
  (inherent to UDP having no handshake).
- **FIN/NULL/XMAS reliability**: Linux, most Cisco gear, BSD, and other
  modern stacks don't reliably follow the RFC 793 behavior these scans
  rely on — this is a real-world limitation of the technique itself
  (documented, not a SpecterScan bug).
- **Service Detection**: intentionally lightweight, no authentication or
  exploit attempts, ever.
- **Raw scan types**: platform-dependent (Linux/WSL2 only, needs
  `CAP_NET_RAW`).
- **Decoys/fragmentation**: SYN-scan, IPv4-only for now — not wired up for
  FIN/NULL/XMAS/ACK/Window or for IPv6 (would need `core/evasion.py`'s
  flag/ack parameters threaded through the IPv6 send path too).
- **IPv6 CIDR expansion** capped at 4096 hosts (a `/64` has 2⁶⁴ addresses —
  silently trying to enumerate that would just exhaust memory). Scan
  individual addresses or `/116`-or-smaller ranges.
- **IPv6 without ancillary data**: hop-limit/TTL isn't available on the
  receive path for IPv6 raw sockets without `cmsg` handling, so
  `os_guess`/`ttl` are `null` for IPv6 results (IPv4 is unaffected).
- Mixed IPv4/IPv6 targets in a single raw-scan run are rejected explicitly
  (run one family at a time).
- REST API has no built-in scan queue or per-client rate limiting — see
  `docs/API.md`.
- Large IPv4 CIDR networks are capped at 65536 hosts (`/16`) per scan run.
- Very high concurrency (`--workers` > ~1000) needs tuning per system
  (file descriptor / ephemeral port limits).

---

## 🚀 Possible Future Work

Nothing here is committed — these are ideas, not a roadmap:

- **Advanced service detection**: protocol-specific probes, version
  fingerprinting, TLS certificate parsing on HTTPS/other TLS ports.
- **Reporting**: XML output, scan-to-scan comparison/diffing.
- **Network interface selection**: explicit interface binding for
  multi-homed scanning hosts.
- **Advanced evasion**: MAC spoofing, timing-profile variation, wiring
  decoys/fragmentation through to the newer scan types and to IPv6.
- **ICMPv6-based host discovery** for IPv6 CIDR ranges (current host
  discovery is TCP-probe based, same as IPv4).

If you want to pick one of these up, see [CONTRIBUTING.md](CONTRIBUTING.md).

---

## 📊 Code Statistics

- **Total lines**: ~3,900 across `core/`, `utils/`, `specterscan.py`,
  `api.py`, and `tests/`
- **Test suite**: 34 tests, 0 external dependencies required to run them
- **Cyclomatic complexity**: low (most functions < 10)

---

## 🔍 Quality Metrics

### Code Quality
- ✅ No external dependencies (pure stdlib), including the REST API
- ✅ Consistent naming conventions
- ✅ Comprehensive docstrings and inline comments (mixed English/Arabic)
- ✅ Type hints throughout
- ✅ Proper exception handling — no raw tracebacks reach end users

### Performance
- ✅ Efficient packet parsing
- ✅ Minimal memory footprint per scan
- ✅ Scalable to 1000+ concurrent probes
- ✅ Rate limiting (fixed or adaptive) prevents network saturation
- ✅ Connection pooling caps concurrent service-detection connections

### Security
- ✅ Input validation on all user inputs (CLI and REST API)
- ✅ No command injection vectors
- ✅ Safe error messages (no sensitive data leak, no tracebacks)
- ✅ Platform/permission checks before raw socket use
- ✅ REST API ships with clear security warnings and optional shared-secret
  auth; documented as local-use-first
- ✅ Plugin system's security model documented explicitly (no sandboxing —
  same trust model as any code you choose to import)

---

## 🛠️ Development Notes

### Architecture Decisions
1. **Pure Python**: portability and maintainability, and it's the whole
   point of the project as a teaching tool.
2. **asyncio**: single-threaded async for efficiency.
3. **Raw sockets for SYN/FIN/NULL/XMAS/ACK/Window**: IPv4 uses
   `IP_HDRINCL` (manual IP header, full control); IPv6 uses the kernel's
   own header construction (`AF_INET6`/`SOCK_RAW`/`IPPROTO_TCP`, no
   `IPV6_HDRINCL`) since that's the more portable, standard pattern on
   Linux — see the comment block above `build_tcp_segment_v6` in
   `core/packet.py` for the full reasoning.
4. **Fallback modes**: connect/UDP for systems without raw socket support.
5. **Modular design**: separate concerns (packet, scanner, evasion,
   service_detector, plugins) — `execute_scan()` in `core/scanner.py` is
   the single reusable entry point both the CLI and the REST API call.

### Testing Strategy
- Unit tests for packet construction/parsing (favor pure functions —
  no root or live network needed to verify most of the logic).
- Validator rules tested directly against small `Opts`-like stand-in
  objects rather than requiring full CLI invocation.
- Manual, documented verification against real local listeners for
  network-dependent behavior (raw socket scans, IPv6) where automated
  testing would need root/specific network setup unavailable in most CI
  environments.

---

## 📞 Support & Documentation

- **README.md** — quick start, all scan types, features, limitations
- **CHANGELOG.md** — version history
- **CONTRIBUTING.md** — how to contribute, ground rules (no deps, no
  exploitation code)
- **SECURITY.md** — legal/ethical use policy, vulnerability reporting
- **docs/API.md** — full REST API reference
- **plugins/README.md** — plugin authoring guide
- Inline comments/docstrings throughout the codebase

---

## 🔐 Security Considerations

**Important**: This tool is for authorized security testing and education
only.
- Only scan networks/systems you own or have explicit permission to test.
- Always comply with applicable laws and regulations — see SECURITY.md.
- Service/banner detection and OS fingerprinting are passive, read-only
  techniques — the tool never attempts authentication or exploitation.
- Do not use for malicious purposes. Maintainers take no responsibility
  for misuse.

---

**Last Updated**: 2026-09-12 (v1.2.0, ~3,900 total lines)
**License**: MIT (see [LICENSE](LICENSE))
