# Changelog

All notable changes to SpecterScan are documented here.

## v1.2.0

### Added
- **IPv6 support**: `syn`/`fin`/`null`/`xmas`/`ack`/`window` scans now work
  against IPv6 targets (`core/packet.py: build_tcp_segment_v6`,
  `core/scanner.py`: family-aware `ScanEngine`). `connect`/`udp` already
  worked transparently via asyncio. A single raw scan run must stay within
  one IP family. IPv6 CIDR expansion is capped at 4096 hosts for safety —
  scan individual addresses or small ranges.
- **Adaptive rate limiting** (`--adaptive-rate`): automatically backs off
  the send rate under high packet loss and recovers it gradually as loss
  drops, instead of a fixed `--rate` throughout the whole scan.
- **Connection pooling** for service/banner detection
  (`core/service_detector.py: ConnectionPool`): caps concurrent outbound
  connections globally and per target host, preventing hundreds of
  simultaneous banner-grab connections from a large scan.
- **REST API** (`api.py`): optional HTTP/JSON interface over the same
  validated scan pipeline the CLI uses, built entirely on
  `http.server` (no new dependencies). See `docs/API.md`.
- **Plugin system** (`core/plugins.py`, `--plugins-dir`): drop a `.py` file
  in `plugins/` to extend service detection (extra port guesses, banner
  regex patterns, or a fully custom async probe) without touching core
  code. See `plugins/README.md`.
- `utils/validator.py` now accepts hostnames (previously — a real
  pre-existing bug — it rejected anything that wasn't a literal IPv4
  address or CIDR block, even though hostname resolution was already
  documented and implemented in `core/scanner.py`).

### Changed
- `core/scanner.run_scan()` split into `execute_scan()` (pure, returns
  structured data, used by both the CLI and the REST API) and a thin
  `run_scan()` CLI wrapper that formats/prints the report.
- `core/packet.py`: `build_syn_packet()` is now a thin wrapper around the
  more general `build_tcp_probe_packet()`.

## v1.1.0

### Added
- Four new raw-socket scan types: `fin`, `null`, `xmas`, `ack`, `window`
  (Priority 1 of the original roadmap).
- `core/packet.py: build_tcp_probe_packet()` — builds a TCP segment with
  any flag combination, not just SYN.
- `PortState.UNFILTERED`, used by `ack` scans to report firewall state
  separately from open/closed.
- Per-scan-type response matching: SYN/FIN/NULL/XMAS match responses on
  the TCP `ack` field; ACK/Window scans match on `seq` (since the probe
  itself sets the ACK field, and RFC 793 has the target echo it back in
  `SEQ` on a stateless RST).
- `utils/validator.py`: new scan types accepted; `--decoys`/`--fragment`
  restricted to SYN scans; `--service-detection`/`--banner` restricted to
  scan types that can actually confirm `open` (`syn`, `connect`, `window`).

## v1.0.1

- Improved error logging in UDP probe failures.
- Removed a redundant port check in packet matching.
- Enhanced debug-log error context.
- Added port-range/CIDR/invalid-input test coverage.

## v1.0.0

- Initial release: TCP SYN stealth scan, TCP connect scan, UDP probing.
- Pure-Python IPv4/TCP packet construction and parsing (checksums per
  RFC 791/793).
- asyncio concurrency, rate limiting, retries, timeouts.
- Decoy IPs and IP fragmentation for SYN scans.
- Heuristic OS fingerprinting (TTL/window).
- Service identification, banner grabbing, reverse DNS.
- Host discovery for CIDR targets.
- JSON/HTML/CSV/text reporting.
- Config file support, structured logging, input validation.
