# NEXUS AI LAB

**Local-first security workspace** — an open-source, read-only static code scanner with a web dashboard and JSON reports.

> v0.1.0 is a heuristic scanner, **not** an autonomous pentester or a CVE database. It does not send code to an AI provider, execute scanned code, or modify files. Scan only projects you own or are authorized to inspect.

## Features

- FastAPI web dashboard (Spanish interface)
- Scan a **configured local directory** of project folders
- Detect possible private key markers, AWS access key IDs, hardcoded secrets, Python debug settings and `eval()` usage
- JSON export with filename, line, severity and remediation suggestions; secret values are never returned
- Read-only Docker mount, limits on file size/count, symlink skipping, no automatic command execution
- Unit/API tests and GitHub Actions CI

## Quick start with Docker

```bash
docker compose up --build
```

Open **http://localhost:8000**. The included `examples/demo.py` project intentionally contains insecure code for demonstration.

To scan your own projects, edit `docker-compose.yml` and change `./examples:/projects:ro` to a local parent directory containing folders of projects. **Only mount directories you are authorized to inspect.** The app is bound to `127.0.0.1` by default; do not expose this unauthenticated service publicly.

## Local Python start

```bash
python -m venv .venv
source .venv/bin/activate  # Windows PowerShell: .venv\\Scripts\\Activate.ps1
pip install -r requirements-dev.txt
export NEXUS_PROJECTS_DIR="$(pwd)/examples" # PowerShell: $env:NEXUS_PROJECTS_DIR="$PWD/examples"
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000; interactive API docs: http://127.0.0.1:8000/docs.

## Tests

```bash
python -m pytest -q
```

## API

- `GET /health` — health check
- `GET /api/projects` — list project directories in the configured root
- `POST /api/scan` — body: `{"project":"demo"}`

## Project layout

```text
app/               FastAPI, scanner, static dashboard
tests/             Scanner and API tests
examples/          Intentionally vulnerable demo
.github/workflows/ CI checks
Dockerfile         Container image
docker-compose.yml Local development
```

## Security notes

This tool reports **potential** findings; false positives and missed issues are possible. It does not check dependencies against live vulnerability feeds. The API has no authentication; keep it on localhost or place it behind authentication before any shared deployment. Avoid scanning large or untrusted file trees. Only plain-text files matching supported extensions are scanned.

## Roadmap

- v0.2: authenticated multi-project dashboard, persistent scan history
- v0.3: dependency/SBOM inventory and advisory database integration
- v0.4: optional AI explanation agents with explicit opt-in
- v1.0: reviewed patch proposals, audit trails and isolated worker execution

## License

Apache License 2.0. See `LICENSE`.
