# NetPi Development Guide

## Five disciplines

### 1. Atomic writes — never partial JSON
All JSON data files must be written via `safe_write_json(path, data)`.
This writes to a `.tmp` file, `fsync`s it, then renames it into place.
Direct `open(path, 'w')` + `json.dump()` is forbidden for any file that could be read concurrently.

### 2. Subprocess hardening — no bare check_output
All subprocess calls must go through `_subprocess_run_safe(cmd, timeout=N, **kwargs)`.
It handles `FileNotFoundError` (missing tool), `TimeoutExpired`, `CalledProcessError`, and sets
`CREATE_NO_WINDOW` on Windows automatically.
Never use `subprocess.check_output` directly in a route handler.

### 3. Page responsibility — one page owns each action
Each write action (validate, generate requirements, generate firewall plan, etc.) is triggered
from exactly one page. Other pages may display the result but must not re-trigger the action.
See `templates/base.html` navigation for the canonical ownership map:
- Validation → `validation.html`
- Requirements → `requirements.html`
- Firewall plan → `firewall.html`
- Device intake → `intake.html`

### 4. API error shape — structured JSON from all /api/ routes
Every `/tools/api/` route that can fail must return:
```json
{ "ok": false, "error": "message", "timestamp": "ISO8601" }
```
The global error handlers in `app.py` catch unhandled exceptions on API paths.
For success responses, always include `"ok": true`.

### 5. Tests must stay green
Run `python -m pytest` (or `run_tests.bat` / `run_tests.sh`) before every commit.
Tests live in `tests/`. Each test module covers one functional area.
The `conftest.py` fixture redirects `DATA_DIR` to a temp directory — no test touches
the real data directory.

## Running locally

```bash
pip install flask openpyxl
python app.py
# → http://localhost:5000/tools/dashboard
```

## Running on the Pi

```bash
git fetch origin
git reset --hard origin/main
# Flask starts automatically via systemd or screen session
```

## Project data layout

```
data/
  <project_id>/
    devices.json
    settings.json
    fingerprints.json
    device_evidence.json
    validation_results.json   (written by validation page)
    requirements.json         (written by requirements page)
    firewall_plan.json        (written by firewall page)
```
