# SpecterScan REST API

`api.py` exposes the same scan engine the CLI uses, as JSON over HTTP,
using only `http.server` from the Python standard library.

```bash
python3 api.py --host 127.0.0.1 --port 8787
# raw scan types (syn/fin/null/xmas/ack/window) need root, same as the CLI:
sudo python3 api.py --host 127.0.0.1 --port 8787
```

## ⚠️ Security first

This API has **no authentication by default**. Anyone who can reach the
port can trigger a network scan *from your machine*. Rules of thumb:

- Keep it bound to `127.0.0.1` (the default) unless you have a specific,
  trusted reason not to.
- If you need remote access, put a real authenticating reverse proxy
  (nginx + mTLS/OAuth, a VPN, etc.) in front of it. Don't expose it
  directly to the internet.
- Optionally set the `SPECTERSCAN_API_KEY` environment variable before
  starting the server to require a matching `X-API-Key` header on every
  request. This is basic shared-secret protection, not a substitute for
  the point above.

```bash
export SPECTERSCAN_API_KEY="something-long-and-random"
python3 api.py
```

```bash
curl -X POST http://127.0.0.1:8787/scan \
    -H 'X-API-Key: something-long-and-random' \
    -H 'Content-Type: application/json' \
    -d '{"target": "127.0.0.1", "ports": "80"}'
```

## Endpoints

### `GET /health`

```json
{"status": "ok", "version": "1.2.0"}
```

### `GET /`

Returns basic service info and a short endpoint summary.

### `POST /scan`

Body: a JSON object. `target` is the only required field; everything else
mirrors the CLI's `scan` options and falls back to the same defaults as
`specterscan.py` (see `config.json`).

| Field | Type | Default | Same as CLI flag |
|---|---|---|---|
| `target` | string (required) | — | positional `target` |
| `ports` | string | `"1-1000"` | `--ports` |
| `scan_type` | string | `"syn"` | `--scan-type` |
| `rate` | int | `500` | `--rate` |
| `timeout` | float | `2.0` | `--timeout` |
| `retries` | int | `1` | `--retries` |
| `workers` | int | `100` | `--workers` |
| `decoys` | int | `0` | `--decoys` |
| `fragment` | bool | `false` | `--fragment` |
| `adaptive_rate` | bool | `false` | `--adaptive-rate` |
| `service_detection` | bool | `false` | `--service-detection` |
| `banner` | bool | `false` | `--banner` |
| `resolve` | bool | `false` | `--resolve` |
| `discover_hosts` | bool | `false` | `--discover-hosts` |
| `output` | string | `"text"` | ignored by the API — response is always JSON |
| `plugins_dir` | string | `"plugins"` | `--plugins-dir` |

Any field not in this table is rejected with `400 Bad Request` (typo
protection — same philosophy as `config.json` validation in the CLI).

#### Example request

```bash
curl -X POST http://127.0.0.1:8787/scan \
    -H 'Content-Type: application/json' \
    -d '{
      "target": "127.0.0.1",
      "ports": "22,80,443",
      "scan_type": "connect",
      "service_detection": true
    }'
```

#### Example response

```json
{
  "tool": "SpecterScan",
  "version": "1.2.0",
  "generated_at": "2026-09-12T11:47:00.239176+00:00",
  "target": "127.0.0.1",
  "scan_type": "connect",
  "duration_seconds": 0.12,
  "statistics": {
    "packets_sent": 3,
    "packets_received": 0,
    "packets_lost": 0,
    "total_results": 3,
    "states": {"open": 2, "closed": 1}
  },
  "results": [
    {
      "host": "127.0.0.1",
      "port": 22,
      "state": "open",
      "protocol": "tcp",
      "latency_ms": 0.42,
      "ttl": null,
      "window": null,
      "os_guess": null,
      "service": "ssh",
      "banner": "SSH-2.0-OpenSSH_9.6",
      "hostname": null,
      "attempts": 1
    }
  ]
}
```

This is exactly `utils/reporter.build_payload()`'s output — the same
structure as `--output json` from the CLI.

### Error responses

All errors are JSON: `{"error": "<message>"}`, with an appropriate HTTP
status code:

| Status | Meaning |
|---|---|
| `400` | Malformed JSON, missing/invalid `target`, unknown field, or a value validation failed (bad port range, unsupported `scan_type`, etc.) |
| `401` | `SPECTERSCAN_API_KEY` is set and the request's `X-API-Key` header didn't match |
| `403` | The server process doesn't have permission for the requested raw-socket scan type — run it as root, or use `scan_type: "connect"`/`"udp"` |
| `404` | Unknown path |
| `413` | Request body too large |
| `422` | Options were well-formed JSON but failed scan-level validation (e.g. `--fragment` with a non-SYN scan type) |
| `500` | Unexpected internal error — details are logged server-side only, never sent to the client |

## Concurrency notes

`api.py` uses `ThreadingHTTPServer`, so concurrent requests run concurrent
scans, each with their own raw sockets/workers. Be mindful of running many
large scans at once on a single machine — there's no built-in global job
queue or scan-count limit in this version.
