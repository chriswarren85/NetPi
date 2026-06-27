# AV NetWorker — Claude Code Reference

## What this project is

AV NetWorker (repo: NetPi) is a Flask-based AV network commissioning and validation tool used on live client sites. It discovers, fingerprints, and validates networked AV devices, then produces structured deliverables: IP schedule, firewall plan, requirements, config scripts, Excel commissioning workbooks, and a full commissioning report.

## Deployment model

| Role | Machine | Actions |
|---|---|---|
| Edit / commit / push | Main laptop (Windows) | Code changes, syntax checks, git — also runs the app for development |
| Source of truth | GitHub | Code history — never edit here directly |
| Primary test + deploy | Field laptop (Windows) | `git pull` → `python app.py` → `curl` tests |

Both laptops are Windows and can run the app and execute commands.
The field laptop is the primary test and deployment target.
Run `curl` endpoint tests against whichever machine is currently running the app (`localhost:5000` on either).

No Linux commands anywhere. No `sudo`, no `systemctl`, no `/etc/` paths.

## Running the app

```
cd C:\pi-projects\NetPi
python app.py
# → http://localhost:5000/tools/dashboard
```

Stopping: Ctrl+C in the terminal.
If EXE is in use: `taskkill /f /im NetPi.exe`

## Backend API check example

```
curl -s -X POST http://localhost:5000/tools/api/validate_systems ^
  -H "Content-Type: application/json" -d "{}" | jq
```

## Codebase facts

- `app.py` — single-file Flask backend: 12,485 lines, 411 functions, 100 routes
- Do not read it top to bottom. Navigate by function name or line number.
- All routes live under `/tools/` and `/tools/api/`
- Root `/` redirects to `/tools/dashboard`
- No `/static` directory — all assets served inline from templates
- Frontend: plain HTML / CSS / JS in Jinja2 templates — no frameworks, no build step
- Storage: JSON files only — no database

## The source of truth rule

`lan_sheet.json` is the operator design register.
It is the authoritative source for firewall plan, requirements, and IP schedule generators.
Fall back to `devices.json` only when no LAN sheet is present.
Key functions: `_load_lan_sheet()`, `_enrich_device_static()`

## Project data layout

```
data/<project_id>/
    lan_sheet.json          ← SOURCE OF TRUTH for generators
    devices.json            ← scan output / fallback only
    settings.json
    fingerprints.json
    device_evidence.json
    validation_results.json
    requirements_cache.json
    firewall_plan.json
    audit_log.json
    operator_notes.json
```

Never hardcode `data/devices.json`. All reads/writes go through `get_project_path()`.
All write endpoints must reject requests with no active project set.

## Five engineering disciplines — mandatory, no exceptions

### 1. Atomic writes
All JSON writes via `safe_write_json(path, data)` — writes `.tmp`, `fsync`, rename.
`open(path, 'w') + json.dump()` is **forbidden** on any file read concurrently.
### 2. Subprocess hardening
All subprocess calls via `_subprocess_run_safe(cmd, timeout=N, **kwargs)`.
Handles `FileNotFoundError`, `TimeoutExpired`, `CalledProcessError`.
Sets `CREATE_NO_WINDOW` on Windows automatically.
Never use `subprocess.check_output` directly in a route handler.

### 3. Page responsibility
Each write action belongs to exactly one page. Other pages display only.

| Action | Owner |
|---|---|
| Device ingestion / commit | `intake.html` |
| Validation | `validation.html` |
| Requirements generation | `requirements.html` |
| Firewall plan + security architecture | `firewall.html` |
| LAN sheet edits | `lan-sheet` template |
| Project settings | `settings.html` |

### 4. API error shape
Every `/tools/api/` route that can fail must return:
```json
{ "ok": false, "error": "message", "timestamp": "ISO8601" }
```
Success responses always include `"ok": true`.

### 5. Tests must stay green
Run `python -m pytest` (or `run_tests.bat`) before every commit.
Tests live in `tests/`. `conftest.py` redirects `DATA_DIR` to a temp directory.
No test touches real project data.

## Development rules

- **grep before touching** — confirm exact function names, field names, route paths before any edit
- **Surgical patches only** — smallest safe change; never rewrite working features
- **Additive API contract** — never rename, remove, or change the type of an existing response key
- **Backend before UI** — verify endpoint behaviour with `curl` before changing any template
- **No logic in templates** — all business logic lives in `app.py`; templates present and confirm only
- **Update PROJECT_STATE.md** whenever behaviour, architecture, or data contracts change

## All current pages

| Route | Purpose |
|---|---|
| `/tools/dashboard` | Live project overview |
| `/tools/devices` | Device inventory — read-only master list |
| `/tools/intake` | All device ingestion |
| `/tools/validation` | Validation runner and results |
| `/tools/firewall` | Firewall plan + security architecture |
| `/tools/requirements` | Communication profiles + requirements |
| `/tools/ipschedule` | IP schedule viewer and export |
| `/tools/recommendations` | Consultant-style recommendations |
| `/tools/report` | Full commissioning report |
| `/tools/settings` | Project settings, VLANs, project switcher |
| `/tools/lan-sheet` | LAN sheet / design register |
| `/tools/scanner` | Ad-hoc network scan and port check |
| `/tools/dns` | DNS entry management |
| `/tools/dhcp` | DHCP lease viewer |
| `/tools/ntp` | NTP status |
| `/tools/network` | Network overview |
| `/tools/diagnostics` | Legacy — redirects to `/tools/intake` |

## Key API endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/tools/api/validate_device` | POST | Per-device validation |
| `/tools/api/validate_all` | POST | Validate all saved devices |
| `/tools/api/validate_systems` | POST | System-level validation |
| `/tools/api/generate_requirements` | POST | Per-device requirements |
| `/tools/api/requirements/saved` | GET | Saved requirements cache |
| `/tools/api/generate_firewall_plan` | POST | IT-ready firewall rule table |
| `/tools/api/security-architecture/saved` | GET | Saved security architecture state |
| `/tools/api/security-architecture/save` | POST | Save security architecture state |
| `/tools/api/generate_flows` | POST | Device-to-device flow map |
| `/tools/api/system_requirements` | POST | Aggregated system-level requirements |
| `/tools/api/recommendations` | POST | Consultant-style recommendations |
| `/tools/api/generate_report` | POST | Full commissioning report payload |
| `/tools/api/ipschedule` | GET | Inventory as IP schedule |
| `/tools/api/lan-sheet` | GET | LAN sheet contents |
| `/tools/api/lan-sheet/save` | POST | Save full LAN sheet |
| `/tools/api/lan-sheet/add` | POST | Add LAN sheet entry |
| `/tools/api/lan-sheet/remove` | POST | Remove LAN sheet entry |
| `/tools/api/lan-sheet/entry` | PATCH | Edit single LAN sheet entry |
| `/tools/api/lan-sheet/infer-vlans` | POST | Auto-assign VLANs from subnets |
| `/tools/api/topology` | GET | CDP/LLDP neighbour map |
| `/tools/api/topology/generate` | POST | Generate topology snapshot |
| `/tools/api/multicast_groups` | GET | Multicast group data |
| `/tools/api/multicast_groups/generate` | POST | Generate multicast snapshot |
| `/tools/api/config-script` | GET | Per-device config script |
| `/tools/api/project/config-scripts/export` | GET | Batch config script ZIP |
| `/tools/api/projects` | GET | List projects |
| `/tools/api/projects/create` | POST | Create project |
| `/tools/api/projects/switch` | POST | Switch active project |
| `/tools/api/projects/delete` | POST | Delete project |
| `/tools/api/project/snapshot` | GET | Export .avp archive |
| `/tools/api/project/restore` | POST | Restore from .avp archive |
| `/tools/api/project/snapshot/compare` | POST | Diff two .avp snapshots |
| `/tools/api/project/version` | GET | Current project version |
| `/tools/api/operator-notes` | GET / PATCH | Project-level notes |
| `/tools/api/audit-log` | GET | Audit log entries |
| `/tools/api/devices` | GET | Device list |
| `/tools/api/devices/add_manual` | POST | Add single device |
| `/tools/api/devices/preview_pasted` | POST | Preview pasted device list |
| `/tools/api/devices/import_pasted` | POST | Import pasted device list |
| `/tools/api/discover_hosts/start` | POST | Start background discovery |
| `/tools/api/discover_hosts/status/<job_id>` | GET | Discovery job status |
| `/tools/api/fingerprint_host` | POST | Fingerprint a single host |
| `/tools/api/fingerprints/confirm` | POST | Confirm AI type suggestion |
| `/tools/api/fingerprints/reject` | POST | Reject AI type suggestion |
| `/tools/api/ai/query` | POST | Natural language project query |
| `/tools/api/ai/recommendations` | POST | AI recommendations |
| `/tools/api/export/xlsx/commissioning_workbook` | GET | Full commissioning workbook |
| `/tools/api/export/xlsx/ip_schedule` | GET | IP schedule xlsx |
| `/tools/api/export/xlsx/firewall_plan` | GET | Firewall plan xlsx |
| `/tools/api/export/xlsx/validation_results` | GET | Validation results xlsx |
| `/tools/api/export/xlsx/change_request` | GET | IT change request template |

## Roadmap status summary

**Complete:** Ch 0–15, Ch 17, Ch 18
**Retrospective complete (implemented, now documented):** Ch 20 (config scripts), Ch 22 (LAN sheet), Ch 23 (network services), Ch 24 (security architecture + requirements persistence)
**Planned:** W10.1 CDP/LLDP (half-done), Ch 19 (native window), Ch 21 (topology canvas W21.0–W21.5), Ch 25 (EXE build W25.0–W25.2)

**Ch 25 note:** `launcher.py` is recorded in the roadmap as created but is NOT present on disk. Confirm with `dir launcher.py` before any EXE build work.

## Device record shape

```json
{
  "ip": "192.168.1.10",
  "hostname": "...",
  "mac": "AA:BB:CC:DD:EE:FF",
  "mac_source": "arp-cache",
  "mac_address": "AA:BB:CC:DD:EE:FF",
  "mac_conflict": false,
  "type": "Dante Audio Device",
  "vlan": "40",
  "make": "...",
  "model": "...",
  "serial": "...",
  "notes": "...",
  "validated": true,
  "validation_result": {}
}
```

MAC source labels: `arp-cache` | `snmp-oid` | `lldp` | `user-entered` | `unknown`
Both `mac` and `mac_address` exist in the codebase — inspect before assuming, never rename either.

## Git workflow

```
# Main laptop — after every change
git add -A
git commit -m "W[chapter].[step] — description"
git push origin windows-migration

# Field laptop — deploy
cd C:\pi-projects\NetPi
git pull origin windows-migration
python app.py
```
