# Contributing to FullRecon

Thanks for taking the time to improve FullRecon. This document explains how to
set up a development environment, what kinds of changes are welcome, and the
bar a pull request needs to clear.

## Ground rules

1. **Authorized use only.** FullRecon is a reconnaissance tool. Contributions
   that add exploitation, credential testing, authentication bypass, or
   destructive behaviour will be rejected.
2. **Scope control is not optional.** Every new network-touching module must
   call `ctx.in_scope(host)` / `scope.allows_url(url)` before sending traffic.
3. **No fake results.** Do not merge code that prints placeholder data, stubs a
   module, or fabricates findings. If a data source is unavailable, degrade
   gracefully and log the limitation.
4. **Respect rate limits.** New modules must use the shared `HttpClient` (or
   honour `cfg.rate_limit`) rather than opening raw sockets in a loop.

## Development setup

```bash
git clone https://github.com/Abobakr-1/FullRecon.git
cd FullRecon
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest -q
```

Optional external tools improve results but are never required:

```bash
sudo apt-get install -y nmap curl jq
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

## Project layout

```
fullrecon/
  cli.py                  argument parsing and entrypoint
  config.py               defaults, config file loading
  core/
    context.py            shared ReconState + ModuleContext
    orchestrator.py       pipeline sequencing
    scope.py              in/out-of-scope decisions
    scanner.py            rate-limited HTTP client
    portscan.py           TCP/nmap scanning engine
    output_manager.py     result directory layout
    report_generator.py   summary.txt / report.json / report.html
  modules/                one file per reconnaissance stage
  utils/                  colours, logging, progress, validators, helpers
tests/                    pytest suite (no network access required)
```

## Adding a module

1. Create `fullrecon/modules/my_module.py` with a class exposing `name`,
   `label`, `__init__(ctx)` and `run() -> dict`.
2. Write results into `ctx.state`, and files through `ctx.out.write(...)`.
3. Register it in `fullrecon/core/orchestrator.py` (`PIPELINE`) and, if useful,
   in `MODULE_GROUPS`.
4. Add a CLI flag in `fullrecon/cli.py` if it makes sense as a shortcut.
5. Add tests. Prefer pure functions and HTML/file fixtures over live requests.

## Testing expectations

- `pytest -q` must pass with no network access.
- New parsing logic needs fixture-based tests (see `tests/test_helpers.py`).
- New scope behaviour needs cases in `tests/test_scope.py`.
- If you touch output layout, update the tree in `README.md`.

## Style

- Python 3.8+ compatible; standard library first.
- Type hints on public functions.
- No new mandatory runtime dependencies without discussion — the tool must
  install cleanly on a bare Kali system with only `dnspython`.
- Keep terminal output readable: one line per host where possible.

## Commit messages

Use a short imperative subject line, optionally with a scope prefix:

```
subdomains: add certspotter pagination
dns: fix dangling CNAME fingerprint for Azure App Service
cli: accept --ports-list ranges
```

## Pull requests

Include in the description:

- what changed and why,
- which modules/files are affected,
- how you verified it (commands run, expected vs actual output),
- any limitation you knowingly left.

## Reporting issues

For a bug, include the FullRecon version (`fullrecon --version`), the exact
command, and the relevant part of `logs/fullrecon.log` with secrets removed.
For a security issue **in FullRecon itself**, do not open a public issue;
contact the maintainer privately first.
