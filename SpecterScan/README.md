# SpecterScan

**A free, open-source, pure-Python network reconnaissance and port-scanning
tool.** No dependencies beyond the standard library. Built for learning how
scanners actually work at the packet level — and genuinely useful for
scanning systems you're authorized to test.

```
python3 specterscan.py scan 192.168.1.10 --ports 1-1000 --service-detection
```

> ⚠️ **Only scan systems you own or have explicit written permission to
> test.** Port scanning systems you don't control can be illegal in many
> jurisdictions and is against the terms of service of most hosting/cloud
> providers. See [Legal & Ethical Use](#legal--ethical-use) below.

---

## Why SpecterScan

- **Zero dependencies.** Everything — TCP/IP packet construction, checksums,
  raw sockets, async concurrency, a REST API — is built on Python's standard
  library alone. Nothing to `pip install`.
- **Educational by design.** The code is heavily commented (mix of English
  and Arabic) to explain *why*, not just *what* — RFC 791/793/8200
  references, checksum algorithms, why each scan type behaves the way it
  does.
- **Actually useful.** Beyond teaching value, it's a working scanner: 8 scan
  modes, service/banner detection, OS fingerprinting, a plugin system, a
  REST API, and JSON/HTML/CSV reporting.

## Features

- **8 scan types**: `syn`, `connect`, `udp`, `fin`, `null`, `xmas`, `ack`, `window`
- **IPv4 and IPv6** targets (single address, hostname, or CIDR range)
- Async concurrency with configurable worker pool, rate limiting (including
  **adaptive** rate limiting that backs off automatically under packet loss)
- Optional evasion techniques for SYN scans: decoy source IPs, IP fragmentation
- Lightweight OS fingerprinting (TTL/window heuristic)
- Service identification + banner grabbing, with a **plugin system** to add
  your own detection rules without touching the code
- Host discovery for CIDR ranges before scanning
- Reports in text, JSON, HTML, or CSV
- Optional **REST API** (`api.py`) — same engine, HTTP/JSON interface
- A real test suite (`tests/test_core.py`, 34 tests, no external test
  dependencies required to write more)

## Requirements

- Python 3.10+
- Linux (or WSL2 on Windows) for raw-socket scan types (`syn`, `fin`, `null`,
  `xmas`, `ack`, `window`) — these need `CAP_NET_RAW`, i.e. `sudo` on most
  systems
- `connect` and `udp` scans work anywhere Python's asyncio sockets work,
  no elevated privileges required

## Installation

```bash
git clone https://github.com/<your-username>/specterscan.git
cd specterscan/SpecterScan
python3 specterscan.py --version
```

That's it — no virtual environment or `pip install` is required for the
core tool (it's pure standard library). If you plan to contribute and want
to run the test suite with `pytest`, see [Development](#development).

## Quick start

```bash
# Fast validation scan, no root required
python3 specterscan.py scan 127.0.0.1 --ports 22,80,443 --scan-type connect

# Classic SYN stealth scan (needs raw sockets -> sudo)
sudo python3 specterscan.py scan 192.168.1.10 --ports 1-1000 --scan-type syn

# With service detection and banners
sudo python3 specterscan.py scan 192.168.1.10 --ports 1-1000 \
    --scan-type syn --service-detection --banner

# UDP probe
python3 specterscan.py scan 192.168.1.10 --ports 53,123,161 --scan-type udp

# Discover live hosts on a /24 first, then scan only those
sudo python3 specterscan.py scan 192.168.1.0/24 --ports 22,80,443 \
    --discover-hosts --scan-type syn

# IPv6
sudo python3 specterscan.py scan 2001:db8::1 --ports 1-1000 --scan-type syn
python3 specterscan.py scan 2001:db8::1 --ports 1-1000 --scan-type connect

# Save a report
python3 specterscan.py scan 192.168.1.10 --ports 1-1000 --output json --report scan.json
python3 specterscan.py scan 192.168.1.10 --ports 1-1000 --output html --report scan.html
```

## Scan types

| `--scan-type` | Needs root? | What it tells you | Notes |
|---|---|---|---|
| `syn` (default) | yes | open / closed / filtered | classic stealth scan, half-open connections |
| `connect` | no | open / closed / filtered | full TCP handshake, works everywhere |
| `udp` | no | open / closed / open\|filtered | UDP has no handshake, so "no response" is ambiguous |
| `fin` | yes | closed / open\|filtered | RFC 793 quirk scan |
| `null` | yes | closed / open\|filtered | no flags at all |
| `xmas` | yes | closed / open\|filtered | FIN+PSH+URG all set |
| `ack` | yes | unfiltered / filtered | detects firewalls, **not** open/closed |
| `window` | yes | open / closed / filtered | ACK probe + TCP window-size heuristic |

**Honest limitation on `fin`/`null`/`xmas`:** these rely on RFC 793 behavior
that Linux, most Cisco gear, BSD, and other modern stacks don't actually
follow — they often send RST regardless of port state, or ignore the probe
entirely. This isn't a bug in SpecterScan; it's a documented, real-world
limitation of the technique itself (the same one nmap's docs describe).
They're included for the educational value of seeing this firsthand, and
because they still work as designed against some embedded/older stacks.

`ack` and `window` scans only make sense combined with a known-open or
known-closed port set from another scan — on their own they tell you about
firewall behavior, not what's actually listening.

## Output formats

`--output text|json|html|csv`, combined with `--report <path>` to write to
a file (HTML/CSV write to a file by default even without `--report`, using
`specterscan_report.html` / `.csv`). JSON without `--report` prints to
stdout — handy for piping into `jq` or other tools.

## Configuration file

`specterscan.py` loads `config.json` from the current directory by default
(override with `--config path.json`). Any CLI flag you pass overrides the
matching config.json value. See the included `config.json` for every
supported key.

## Evasion options (SYN scan only, IPv4 only)

```bash
sudo python3 specterscan.py scan 10.0.0.5 --ports 80 --scan-type syn --decoys 5
sudo python3 specterscan.py scan 10.0.0.5 --ports 80 --scan-type syn --fragment
```

`--decoys` and `--fragment` are currently restricted to `--scan-type syn`
on IPv4 (see [Limitations](#limitations)).

## Adaptive rate limiting

```bash
sudo python3 specterscan.py scan 10.0.0.0/24 --ports 1-1000 --scan-type syn \
    --rate 2000 --adaptive-rate
```

Starts at `--rate` packets/second and automatically slows down when packet
loss climbs above 20%, gradually speeding back up (never below your
starting rate) once loss drops under 5%. Useful for large scans where you
don't want to hand-tune `--rate` for every network.

## Plugins

Drop a `.py` file in `plugins/` to extend service detection — no code
changes required. See [`plugins/README.md`](plugins/README.md) and
[`plugins/examples/custom_service_example.py`](plugins/examples/custom_service_example.py)
for the full contract (`PORT_MAP`, `PATTERNS`, and a custom async `probe()`
hook). Disable with `--plugins-dir ""`.

## REST API

```bash
python3 api.py --host 127.0.0.1 --port 8787
curl -X POST http://127.0.0.1:8787/scan \
    -H 'Content-Type: application/json' \
    -d '{"target": "127.0.0.1", "ports": "22,80,443", "scan_type": "connect"}'
```

Same validated pipeline as the CLI (`utils/validator.py` +
`core.scanner.execute_scan`), exposed as JSON over HTTP using only
`http.server` from the standard library. **Read the security warning at the
top of `api.py` before exposing this beyond `127.0.0.1`** — it ships with no
authentication by default (optional shared-secret auth via the
`SPECTERSCAN_API_KEY` environment variable and the `X-API-Key` header).
Full endpoint reference: [`docs/API.md`](docs/API.md).

## Project structure

```text
SpecterScan/
├── specterscan.py          # CLI entry point (argparse, config merging, error handling)
├── api.py                  # optional REST API (stdlib http.server only)
├── config.json              # example/default config file
├── core/
│   ├── packet.py            # IPv4/IPv6 + TCP header construction & parsing (pure struct/socket)
│   ├── scanner.py            # ScanEngine, target/port expansion, rate limiting, orchestration
│   ├── service_detector.py   # service ID, banner grabbing, connection pooling
│   ├── evasion.py            # decoys, IP fragmentation (SYN/IPv4 only)
│   └── plugins.py            # plugin loader
├── utils/
│   ├── validator.py          # input validation (target/ports/options)
│   ├── logger.py             # structured, colored logging
│   └── reporter.py           # text/JSON/HTML/CSV report generation
├── plugins/                  # drop your own .py plugins here (see plugins/README.md)
└── tests/
    └── test_core.py
```

## Limitations

- OS detection is heuristic (TTL/window based), not definitive.
- UDP no-response results are inherently ambiguous (`open|filtered`).
- Service detection is intentionally lightweight — no authentication or
  exploit attempts against detected services, ever.
- Raw scan types (`syn`/`fin`/`null`/`xmas`/`ack`/`window`) need
  `CAP_NET_RAW` — Linux/WSL2 only, not native Windows.
- `--decoys`/`--fragment` are SYN-scan/IPv4-only for now.
- `--service-detection`/`--banner` only run against scan types that can
  actually confirm a port is open (`syn`, `connect`, `window`).
- IPv6 CIDR ranges are capped at 4096 addresses per scan (a `/64` has
  2⁶⁴ addresses — expanding one is not something any tool should attempt
  silently). Scan individual addresses or small ranges (`/116` or smaller).
- No IPv6 support for `--decoys`/`--fragment` yet.
- A single scan run is restricted to one IP family (v4 or v6) at a time for
  raw scan types.

## Development

```bash
cd SpecterScan
python3 -m pytest tests/ -v        # if you have pytest installed
# or, with zero extra dependencies:
python3 -c "
import tests.test_core as t
for name in dir(t):
    if name.startswith('test_'):
        getattr(t, name)()
        print('PASS', name)
"
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Legal & Ethical Use

SpecterScan sends real packets to real hosts. Before scanning anything:

- **Only scan systems you own, or have explicit, documented authorization
  to test.** This includes your own lab VMs, `127.0.0.1`, and networks you
  personally administer.
- Unauthorized port scanning is illegal under computer-crime laws in many
  countries (e.g., the U.S. Computer Fraud and Abuse Act, the UK Computer
  Misuse Act) and is grounds for account termination under nearly every
  cloud/hosting provider's acceptable-use policy — even when no exploitation
  follows.
- The maintainers of this project take no responsibility for misuse. This
  tool is released for education and authorized security testing only. See
  [SECURITY.md](SECURITY.md) for responsible-disclosure and reporting policy.

## License

MIT — see [LICENSE](LICENSE). Free to use, modify, and redistribute,
including commercially, with attribution.

## Contributing

Issues and pull requests are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).
