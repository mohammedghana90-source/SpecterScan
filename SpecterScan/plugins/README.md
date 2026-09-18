# SpecterScan Plugins

Drop a `.py` file directly in this folder (`plugins/`, not a subfolder) to
extend service detection without touching SpecterScan's own code. It's
loaded automatically on every scan that uses `--service-detection` or
`--banner`.

A plugin file can define any of these (all optional):

```python
PORT_MAP = {9999: "my-custom-app"}          # extra port -> service guesses
PATTERNS = [(r"mycustomserver/", "my-custom-app")]  # extra banner regex patterns

async def probe(host: str, port: int, timeout: float) -> str | None:
    ...  # fully custom banner-grab logic for a specific protocol
```

Plugins only **add** to detection — they never override a built-in match in
`core/service_detector.py`. See `examples/custom_service_example.py` for a
complete, runnable example (copy it up one directory to activate it).

## Disabling plugins

```bash
python3 specterscan.py scan 127.0.0.1 --ports 80 --service-detection --plugins-dir ""
```

or point `--plugins-dir` at a different (e.g. empty) directory.

## Security

Plugins are plain Python, executed with the same privileges as SpecterScan
itself — there is no sandboxing. Only add plugins you wrote yourself or
trust completely, the same way you would with a browser extension or editor
plugin.
