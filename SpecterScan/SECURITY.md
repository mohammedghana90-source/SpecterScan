# Security & Responsible Use Policy

## This is a network scanning tool — read this first

SpecterScan sends real TCP/UDP packets to real hosts, including raw-socket
SYN/FIN/NULL/XMAS/ACK/Window probes. **Only use it against systems you own,
or for which you have explicit, documented authorization to test.**

Scanning systems without authorization can:

- Violate computer-crime laws in most countries (e.g., the U.S. Computer
  Fraud and Abuse Act, the UK Computer Misuse Act, and equivalents
  elsewhere), regardless of whether any vulnerability is exploited.
- Violate the acceptable-use policy of essentially every cloud/hosting
  provider (AWS, GCP, Azure, DigitalOcean, etc.), which can result in
  account suspension even for authorized customers scanning their own
  resources if the provider wasn't separately notified per their policy.
- Trigger intrusion-detection/incident-response processes on the target
  network, consuming other people's time and resources even when no harm
  was intended.

**When in doubt, don't scan it.** Use `127.0.0.1`, a local VM, or a
dedicated lab network (many providers, e.g. Hack The Box, offer legal
scanning targets for practice).

## Reporting a vulnerability in SpecterScan itself

If you find a security issue in SpecterScan's own code (e.g., something
that could let a malicious *scan target* achieve code execution against the
*scanner*, a parsing bug that crashes on crafted responses, or an issue in
the REST API's input handling), please report it privately rather than
opening a public issue:

- Open a [GitHub Security Advisory](../../security/advisories/new) on this
  repository (preferred), or
- Email the maintainer listed in the repository's GitHub profile.

Please include:
- A description of the issue and its impact
- Steps to reproduce (a minimal crafted packet/response, if applicable)
- The version/commit you tested against

We'll acknowledge reports within a reasonable timeframe and credit
reporters in the changelog unless you'd prefer to stay anonymous.

## Scope notes

- SpecterScan does **not** attempt authentication or exploitation against
  any detected service — service/banner detection is read-only and passive
  by design. A report claiming otherwise as a "vulnerability" is out of
  scope; that's simply not something this tool does.
- The bundled REST API (`api.py`) ships with no authentication by default
  and is documented as local-use-only. Exposing it unauthenticated to an
  untrusted network is a deployment/configuration choice, not a
  vulnerability in the code — see the warning at the top of `api.py` and in
  [docs/API.md](docs/API.md).
- The plugin system (`core/plugins.py`) executes arbitrary Python code from
  files you choose to place in your plugins directory, by design, with no
  sandboxing — this is documented in `plugins/README.md`. Loading a plugin
  you don't trust is equivalent to running any other untrusted Python
  script.
