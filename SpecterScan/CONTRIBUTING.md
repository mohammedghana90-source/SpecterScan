# Contributing to SpecterScan

Thanks for considering a contribution — issues, bug reports, docs fixes,
and pull requests are all welcome.

## Ground rules

- **Pure standard library, no exceptions.** SpecterScan's entire value
  proposition is "no dependencies, read the packet-construction code
  yourself." A PR that adds `pip install`-able dependencies to the core
  tool (`core/`, `utils/`, `specterscan.py`, `api.py`) will not be merged.
  Optional dev tooling (e.g. `pytest`, linters) is fine as long as the tool
  itself still runs with zero installs.
- **No exploitation or offensive payloads.** Service detection stays
  read-only (banner grabbing, port/pattern matching). PRs that add
  authentication attempts, exploit code, or payload delivery against
  scanned services will be declined regardless of how they're framed
  ("just for testing", behind a flag, etc.) — that's a different kind of
  tool than this one.
- **Keep the comments.** A lot of the value here is educational — code
  explaining *why* a checksum algorithm works the way it does, or why FIN
  scans behave inconsistently across OSes. Please keep (and add to) that
  style rather than stripping comments for brevity.

## Getting started

```bash
git clone https://github.com/<your-username>/specterscan.git
cd specterscan/SpecterScan
python3 specterscan.py --version
```

No build step, no virtualenv required for the tool itself.

## Running tests

```bash
python3 -m pytest tests/ -v
```

If you don't have `pytest` installed, the test functions are plain
functions with no fixtures beyond simple classes, so you can also run:

```bash
python3 -c "
import tests.test_core as t
for name in dir(t):
    if name.startswith('test_'):
        getattr(t, name)()
        print('PASS', name)
"
```

Please add tests for new packet-building logic, validator rules, or
scan-type behavior — most of the existing suite tests pure functions
(packet construction/parsing, validation, rate limiting) precisely because
they don't need root or a live network to verify.

## Making changes

1. Fork the repo and create a branch from `main`.
2. Make your change. Keep PRs focused — one feature or fix per PR is much
   easier to review than a bundle of unrelated changes.
3. Run the test suite and add tests for new behavior.
4. Update `README.md`/`PROGRESS.md`/`docs/API.md` if you changed
   user-facing behavior (new CLI flag, new scan type, new API field, etc.).
5. Open a PR describing what changed and why. Link any related issue.

## Reporting bugs

Open a GitHub issue with:
- What you ran (exact command / API request)
- What you expected vs. what happened
- Your OS and Python version (`python3 --version`)
- Full error output if there was a crash (SpecterScan is designed to never
  leak a raw traceback to normal users — if you see one, that's itself a
  bug worth reporting, run with `--log-level DEBUG` for more detail)

## Reporting security issues

Please don't open a public issue for security-sensitive bugs — see
[SECURITY.md](SECURITY.md) for how to report those privately.

## Code style

- Follow the existing style in the file you're editing rather than
  imposing a new one — this codebase mixes a fairly verbose,
  heavily-commented style (especially in `core/`) intentionally, for
  educational readability over line-count brevity.
- Type hints are used throughout (`from __future__ import annotations` +
  builtin generics like `list[int]`) — please keep using them.
- Arabic comments exist alongside English ones in several files
  (historical — the project started with Arabic-first documentation).
  Either language is fine for new comments; consistency within a single
  function/block matters more than a global language choice.
