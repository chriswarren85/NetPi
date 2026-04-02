# NetPi Project State

## System Overview
NetPi is a Raspberry Pi-based AV network commissioning tool.

- Flask backend (app.py)
- nginx reverse proxy at /tools
- Web UI in templates/diagnostics.html

---

## Core Capabilities (WORKING)

### Network Discovery
- VLAN-aware subnet selection
- Host discovery via nmap (-sn)
- Hostname resolution:
  - reverse DNS
  - mDNS (avahi)

### Device Identification
- MAC address extraction
- Vendor lookup
- Vendor → device type inference (guess_type_from_vendor)

### Fingerprinting
- Targeted nmap port scan
- Expanded AV-aware port list
- Multi-layer classification:
  1. Port-based detection
  2. Vendor refinement
  3. Combined logic

- Runs automatically in background (UI)
- Updates “Likely type” dynamically

---

## Device Management

### Bulk Add (NEW)
- Select multiple discovered devices
- Sends:
  - IP
  - hostname
  - VLAN
  - type (fingerprint/vendor derived)
  - MAC
  - vendor

### Single Add
- Per-device add button
- Uses fingerprint result

### Auto Naming (NEW)
Backend naming system:

- display → LCD-##
- projector → PJ-##
- camera → CAM-##
- network-device → SW-##
- crestron / control → CP-##
- qsys / biamp / shure / dante → DSP-##
- novastar → VX-##
- lighting (artnet/sacn/grandma) → LGT-##
- printer → PRN-##
- fallback → DEV-##

Handled by:
- device_name_prefix()
- generate_device_name()

---

## UI Features

### Toolbar (UPDATED)
- Left:
  - VLAN select
  - Run Checks
  - Discover Hosts
  - Cancel Discovery (AbortController)

- Right:
  - Add Selected (bulk add)
  - Export CSV
  - Open Report
  - Manage Devices

### Discovery Table
- Checkbox selection
- Hostname / IP / MAC / Vendor
- Status badge
- Likely type:
  - initial vendor guess
  - updated via fingerprinting
- Actions:
  - Quick port scan
  - Add to devices

### Background Behavior
- Discovery is async
- Fingerprinting runs per device
- Cancel button aborts frontend request

---

## Important Backend Functions

- guess_type_from_vendor()
- fingerprint_host()
- add_bulk_devices()
- add_discovered_device()
- generate_device_name()
- device_name_prefix()

---

## Known Constraints / Rules

- Do NOT rewrite working fingerprint_host()
- Do NOT break add_bulk_devices()
- Do NOT remove background fingerprinting
- Prefer extending logic instead of replacing
- Keep changes incremental and testable

---

## Current Architecture Strength

NetPi now operates as a **2-stage intelligence system**:

1. Fast classification (vendor/MAC)
2. Accurate refinement (port fingerprinting)

This mimics professional network discovery tools.

---

## Next Feature (IN PROGRESS)

Paste-based device import:

- Paste Excel (tab-separated) data
- Auto-detect headers:
  - Name, IP, VLAN, Type, MAC, Vendor, Notes
- Validate IPs
- Infer missing type
- Auto-name missing names
- Preview before import
- Bulk add using existing system
- Skip duplicates

---

## Chat Continuity Instruction (IMPORTANT)

When continuing in a new chat:

- Treat this file as the **source of truth**
- Do NOT rebuild existing features
- Only extend functionality

Before making changes:
1. Read this state
2. Ask for missing context if unsure
3. Apply minimal, surgical edits

---

## Auto-Update Instruction

After each completed feature, append:

### Last Update
- Feature:
- Files modified:
- Summary of changes:

The assistant should always:
- Update this section
- Keep the document current
- Avoid duplicating existing functionality


### Last Update
- Feature: Paste-based device import (Devices page integration)
- Files modified:
  - app.py
  - templates/devices.html
- Summary of changes:
  - Implemented Excel-style paste import system
  - Added backend parsing with header detection and validation
  - Added preview API with duplicate and invalid row detection
  - Integrated paste workflow into Devices page UI
  - Added preview → add → save workflow using existing deviceList system
  - Ensured compatibility with existing saveDevices() logic
  - Preserved all existing discovery and fingerprinting functionality



---

## API Testing Rules

- ALWAYS use curl for testing endpoints when possible
- Prefer curl over browser testing for debugging
- Always provide exact curl commands ready to paste
- Use jq for readable output when appropriate



---

## Safe Editing Rules

- ALWAYS inspect files with grep or sed before modifying
- NEVER assume exact code blocks exist
- Match and replace only verified text
- If a patch fails, stop and re-check structure
- Prefer incremental inserts over replacements



---

## Deep Validation Goals

Validation should evolve beyond simple checks:

### Network Intelligence
- Identify open TCP ports per device
- Track accessible services (HTTP, HTTPS, SSH, etc.)
- Record latency and responsiveness

### Service Awareness
- HTTP title extraction
- SSL detection
- API endpoint reachability (future)

### Output Structure Expansion

Validation results should include:

- open_ports: [80, 443]
- service_map: {80: "http", 443: "https"}
- latency_ms
- check_details

### Long-Term Direction

NetPi should function as:

- Lightweight AV-aware scanner
- Deployment validation engine
- Commissioning verification tool



---

## Debugging Standard (MANDATORY)

- ALWAYS use curl-first debugging for backend endpoints
- NEVER rely on browser testing when debugging APIs
- ALWAYS provide curl commands BEFORE suggesting code changes
- ALWAYS verify endpoint responses with curl before UI debugging



---

## Pre-Edit Inspection Protocol (MANDATORY)

Before modifying ANY file:

1. Run grep to confirm code location
2. Verify exact strings exist
3. If not found → STOP and reassess
4. Only patch confirmed text

This prevents breaking working UI or backend logic.



---

## Validation Output Contract (STRICT)

All validation results should follow this structure:

{
  "ip": "192.168.1.20",
  "name": "DSP-01",
  "type": "qsys",
  "overall": "pass|fail|warn",
  "latency_ms": number,
  "open_ports": [80, 443],
  "service_map": {
    "80": "http",
    "443": "https"
  },
  "results": [
    {
      "check": "ping|port:80|http",
      "status": "pass|fail|warn",
      "detail": "string"
    }
  ]
}

Rules:
- open_ports must be derived automatically
- service_map must be inferred from ports
- results must remain lightweight (fast checks only)
- total validation time per device must stay under ~3 seconds


## Cross-device system validation

Added backend cross-device readiness validation for AV systems.

### New backend capability
- `run_system_validation(devices)` in `checks/validation.py`
- New API endpoint: `POST /tools/api/validate_systems`

### Current system validation rules
- `crestron_control_to_qsys`
  - checks whether a Crestron control processor and Q-SYS device both validate successfully
  - requires target Q-SYS port `1710`
- `crestron_control_to_biamp`
  - checks whether a Crestron control processor and Biamp/Tesira device both validate successfully
  - requires any of target ports `80`, `443`, or `23`
- `crestron_uc_to_touchpanel`
  - checks whether a Crestron UC engine and touch panel both validate successfully
  - requires target ports `41795` and `443`
### Important limitation
These are readiness / inference checks based on NetPi observations.
They do **not** yet prove a source-initiated session from the actual AV endpoint itself.
They are intended to answer:
- "Does this system look ready?"
- "Are expected services exposed?"
- "Is the target side presenting the required ports?"

### Prompting / workflow note
Treat `PROJECT_STATE.md` as source of truth.
Always inspect files with `grep` before patching.
Always use `curl` to test backend endpoints before UI work.
Prefer small surgical patches over file rewrites.


## NetPi V5 — Auto Device Typing + System Graph Mapping
Date: 2026-03-30

### Completed in this session

#### Auto device typing
- Added safe auto-typing helper logic in `app.py`
- Auto-typing uses:
  - `observed_platform.platform`
  - `fingerprint.platform`
- Preference order:
  1. `observed_platform`
  2. `fingerprint`
- Auto-promote only when confidence is strong
- Conservative behavior:
  - do not force type changes for weak/unknown matches
  - only apply when current type is weak/mismatched and confidence is high
- Added `auto_type` object to per-device validation response from:
  - `POST /tools/api/validate_device`

#### Auto-type apply endpoint
- Added:
  - `POST /tools/api/auto_type_devices`
- Endpoint runs validation per device and safely updates device types when strong matches exist
- Confirmed working:
  - `DEV-02` auto-promoted from `web-device` to `qsys`

#### Devices file compatibility fix
- Fixed `load_devices()` in `app.py`
- `load_devices()` now supports both formats:
  - legacy dict format: `{"devices": [...]}`
  - flat list format: `[...]`
- Prevents crashes when `devices.json` is a top-level list

#### System graph backend
- Added system graph builder in `app.py`
- `build_detected_systems(devices, system_results)` now returns:
  - `systems`
  - `mode`
  - `edge_count`
- Added relationship model:
  - `from`
  - `to`
  - `type`
  - `source_check`
  - `inferred`
- Graph currently supports:
  - real rule-based edges when source/target pairs exist
  - inferred fallback edges when only grouped peers exist

#### Current system graph behavior
- Current `validate_systems` output includes:
  - `detected_systems`
- Current mode observed:
  - `type_grouping`
- Current inferred graph result observed:
  - `NV21-01 -> DEV-02 (peer)`
- Current fallback behavior:
  - if no real system-rule edges exist, graph builder groups compatible AV device types and creates inferred `peer` relationships

#### UI — Detected Systems panel
- Added Detected Systems section to `templates/devices.html`
- Added `renderDetectedSystems(data)` function
- Hooked Detected Systems rendering into:
  - `runSystemValidation()`
- UI now displays:
  - detected system id
  - summary chain
  - device list
  - relationship rows
  - relationship badge (`peer`)
  - inferred marker when applicable

### Current known state
- Working:
  - per-device validation
  - validate all
  - system validation
  - auto-type response in validate_device
  - auto-type bulk apply endpoint
  - detected systems backend response
  - detected systems frontend panel
- Current graph is still mostly fallback/inferred because system validation rules are skipping when required typed devices are not yet present
- Existing system validation rules in `checks/validation.py` remain:
  - `crestron_control_to_qsys`
  - `crestron_control_to_biamp`
  - `crestron_uc_to_touchpanel`

### Important implementation notes
- `PROJECT_STATE.md` remains the single source of truth
- Do not rewrite working features
- Do not break:
  - `renderTable()`
  - pasted-device import parser
  - existing validation endpoints
  - working System Checks panel
- Prefer grep-first inspection and surgical patches
- Always test backend endpoints with `curl` before UI work
- Safe patching was required because several exact-text anchors in `devices.html` differed from expected formatting

### Best next step
Improve strong auto-typing for real AV roles so system-rule graph edges can become real instead of inferred.

Priority targets:
1. Crestron control processors
2. Crestron touch panels
3. Crestron UC engines
4. Biamp / Tesira devices

Desired outcome of next step:
- More accurate device roles in `devices.json`
- `run_system_validation()` begins producing real `from_device` / `to_device` pairs
- `detected_systems.mode` shifts from fallback `type_grouping` toward real graph relationships
- UI displays relationships such as:
  - `CP-01 -> DSP-01 (control)`
  - `DSP-01 -> TP-01 (ui)`

### Endpoint reminders
- Per-device validation:
  - `POST /tools/api/validate_device`
- Bulk validation:
  - `POST /tools/api/validate_all`
- System validation:
  - `POST /tools/api/validate_systems`
- Auto-type apply:
  - `POST /tools/api/auto_type_devices`

### Current observed example
- Auto-typing successfully changed:
  - `DEV-02`: `web-device` -> `qsys`
- Current detected systems example:
  - `NV21-01 -> DEV-02 (peer)`


## NetPi Development Workflow Standard (Persistent)

This section defines how ChatGPT should respond in ALL future NetPi chats.

### Core behavior rules (DO NOT REPEAT IN FUTURE CHATS)
- Treat PROJECT_STATE.md as the single source of truth
- Do not restate these rules in future chats
- Assume these rules are already known and active

### Development principles
- NEVER rewrite working features
- ALWAYS apply small, surgical patches
- ALWAYS inspect files with grep before modifying
- ALWAYS verify backend with curl before touching UI
- NEVER break:
  - renderTable()
  - pasted-device parser
  - existing API endpoints
- Prefer safe patch scripts over inline editing
- Avoid fragile string matching when possible

---

## Command-Driven Workflow Mode (Default)

All future responses should follow this structure:

### 1. INSPECT
Provide exact commands:
- grep
- nl
- sed -n

### 2. PATCH
Provide:
- backup command
- safe patch script (python or sed)
- exact insertion/replacement logic

### 3. RESTART
Always include:
sudo systemctl restart netpi
sudo systemctl restart nginx

### 4. VERIFY (MANDATORY)
Always include curl:
curl -s -X POST http://127.0.0.1/tools/api/<endpoint> | jq .

### 5. EXPECTED RESULT
Explain what should change:
- backend response
- UI behavior (if applicable)

### 6. NO FLUFF
- No long explanations unless requested
- Focus on execution

---

## Expanded AV Role Inference Targets

Priority device role detection MUST include:

### Core AV roles
1. Crestron control processors
2. Crestron touch panels
3. Crestron UC engines
4. Biamp / Tesira devices

### Q-SYS ecosystem (NEW PRIORITY)
5. Q-SYS Core (DSP)
6. Q-SYS NV endpoints:
   - NV-21
   - NV-32-H
7. Q-SYS Touch Panels (TSC series)
8. Q-SYS peripherals (QIO, etc.)

### Detection expectations
- Use:
  - observed ports
  - fingerprint platform
  - known service ports
- Prefer HIGH CONFIDENCE promotion only
- Avoid false positives

---

## Target System Graph Evolution

Current:
- mode: type_grouping
- inferred peer edges

Target:
- mode: graph
- real edges:
  - crestron_control -> qsys_core
  - qsys_core -> touchpanel
  - uc_engine -> touchpanel
  - qsys_nv -> qsys_core

---

## Instruction to Future Chats

DO NOT re-ask for:
- workflow structure
- patch style
- command format

ASSUME:
- command-driven workflow is required
- safe patching is required
- curl verification is required


### Last Update
- Feature: System validation backed by target port evidence for Q-SYS Core to NV relationships
- Files modified:
  - checks/validation.py
  - PROJECT_STATE.md
- Summary of changes:
  - Added lightweight system-rule target port evidence collection using existing TCP probing helper
  - Populated `required_target_ports`, `observed_target_ports`, and `target_open_ports` for Q-SYS Core to NV checks
  - Switched system rule pass/fail to use observed network evidence instead of broad device `overall` validation status

### Last Update
- Feature: Stricter Q-SYS inference and clearer system skip messaging
- Files modified:
  - app.py
  - checks/validation.py
  - PROJECT_STATE.md
- Summary of changes:
  - Tightened Q-SYS role inference so generic web devices are no longer treated as Q-SYS from weak signals alone
  - Prevented low-confidence Q-SYS fingerprint fallback from reinforcing stale or weak auto-typing
  - Improved system validation skip reasons with Q-SYS-specific missing-device messages

### Last Update
- Feature: Removed legacy generic Q-SYS touchpanel rule
- Files modified:
  - app.py
  - checks/validation.py
  - PROJECT_STATE.md
- Summary of changes:
  - Removed the older `qsys_to_touchpanel` system rule so Q-SYS messaging now follows the stricter `qsys-core` to `qsys-touchpanel` model
  - Dropped the stale graph label mapping tied to the removed generic Q-SYS touchpanel rule

### Last Update
- Feature: Suppressed weak fallback type grouping for single-role AV evidence
- Files modified:
  - app.py
  - PROJECT_STATE.md
- Summary of changes:
  - Updated fallback detected-system grouping to return no inferred systems when only one AV role is present
  - Preserved the `detected_systems` output shape while reducing noisy peer groupings from incomplete role evidence

### Last Update
- Feature: Diagnostics discovery bulk-add cleanup
- Files modified:
  - app.py
  - templates/diagnostics.html
  - PROJECT_STATE.md
- Summary of changes:
  - Removed the pasted-device import UI from diagnostics only and left the Devices page import workflow unchanged
  - Added diagnostics-side `Add All Discovered` action backed by a new `/tools/api/devices/add_all_discovered` endpoint
  - Reused shared discovered-device add logic so duplicate IPs are skipped and bulk add returns `added`, `skipped_existing`, and `total_seen`

### Last Update
- Feature: Diagnostics post-add fingerprint follow-up and per-row VLAN editing
- Files modified:
  - app.py
  - templates/diagnostics.html
  - templates/devices.html
  - PROJECT_STATE.md
- Summary of changes:
  - Extended `/tools/api/devices/add_all_discovered` to return the newly added IP set for targeted follow-up actions without changing duplicate-skip behavior
  - Added a diagnostics-side `Fingerprint Added Devices` action that only fingerprints the devices added by the last bulk add
  - Made the Devices page VLAN cell editable per row while preserving the existing `deviceList` plus `saveDevices()` persistence flow into `devices.json`
## Execution Boundaries � Local vs Pi

NetPi follows a strict separation between development environment and runtime environment.

### Laptop (Windows / Dev Environment)
- Used for:
  - Code editing
  - Planning
  - Static analysis
  - Syntax checks (e.g. python -m py_compile app.py)
- NOT used for:
  - Running NetPi backend endpoints
  - curl testing against /tools/api/*
  - Any network validation or discovery logic

### Raspberry Pi (Runtime / Source of Truth for Execution)
- The ONLY environment where:
  - Flask app is running
  - nginx is serving /tools
  - devices.json is live
  - Network discovery and fingerprinting are valid

### Critical Rule
- NEVER run curl or endpoint tests from outside the Pi
- NEVER assume localhost on dev machine == NetPi runtime

### Required Testing Pattern
All endpoint testing must be executed manually on the Pi using:

curl -s http://127.0.0.1/tools/...

### Codex / Assistant Behavior
- Must NOT attempt to execute curl requests outside the sandbox
- Must NOT simulate network results
- Must ALWAYS provide:
  1. Exact curl commands for Pi
  2. Expected response shape
  3. What success/failure looks like

### Deployment Flow
1. Edit code locally
2. Syntax check locally (optional)
3. Deploy to Pi
4. Run curl tests on Pi
5. Verify in browser via nginx (/tools)

This separation is mandatory and must not be bypassed.

### Last Update
- Feature: Auto-assign VLAN from subnet on device add/import
- Files modified:
  - app.py
  - templates/devices.html
  - PROJECT_STATE.md
- Summary of changes:
  - Added backend CIDR-based VLAN inference with a default 10.110.50.0/24 -> AV_Control mapping
  - Applied VLAN autofill only when incoming devices have no VLAN set across discovered-device add, add-all discovered, pasted import, preview, and save flows
  - Updated Devices save handling so backend-normalized VLAN values are reflected in the UI after save without changing the existing table flow

### Last Update
- Feature: Settings-driven VLAN inference and read-only Devices VLAN UI
- Files modified:
  - app.py
  - templates/devices.html
  - PROJECT_STATE.md
- Summary of changes:
  - VLAN assignment is now inferred automatically from settings.json lans[].subnet using each VLAN 
ame as the saved label
  - settings.json lans is now the sole source of truth for subnet-based VLAN mapping, with blank or unmatched subnets saving blank VLAN values
  - Removed manual VLAN editing from the Devices UI while keeping VLAN visible and filterable as a read-only field

### Last Update
- Feature: Validate All repair and fingerprint type persistence
- Files modified:
  - app.py
  - templates/diagnostics.html
  - PROJECT_STATE.md
- Summary of changes:
  - Repaired the Devices page Validate All regression after the VLAN UI cleanup by restoring a valid backend response shape
  - Fingerprinting now persists updated device types for matching saved devices when a weak stored type can be safely promoted to a stronger inferred type
  - Diagnostics fingerprint follow-up now reports how many saved device type updates were written during the run

### Last Update
- Feature: guessed_type now follows fingerprint platform
- Files modified:
  - app.py
  - PROJECT_STATE.md
- Summary of changes:
  - Updated /tools/api/fingerprint_host so guessed_type now derives from ingerprint.platform when a strong platform is identified
  - Preserved the existing fallback guess logic for cases where fingerprint platform remains unknown
  - Left the existing saved-device persistence logic unchanged so type promotion now works naturally once guessed_type is stronger

### Last Update
- Feature: fingerprint_host now uses rich validation fingerprinting
- Files modified:
  - app.py
  - PROJECT_STATE.md
- Summary of changes:
  - Updated /tools/api/fingerprint_host to reuse the same un_validation() path as alidate_all, including HTTP title and observed platform evidence
  - guessed_type now prefers the rich validation fingerprint and observed platform results before falling back to weak web-device style guesses
  - Preserved the existing response shape and conservative saved-device type persistence behavior

### Last Update
- Feature: Connectivity matrix backend wired into validate_systems response
- Files modified:
  - app.py
  - PROJECT_STATE.md
- Summary of changes:
  - Wired the Segment 1 connectivity evaluator into `POST /tools/api/validate_systems` without changing existing `results` or `detected_systems` response keys
  - Added backend-only `connectivity`, `connectivity_summary`, and `connectivity_note` response fields
  - Added failure-safe handling so connectivity matrix evaluation errors do not break base system validation output
  - Deferred all UI rendering changes for a later segment
### Last Update
- Feature: Connectivity matrix UI rendering on Devices page
- Files modified:
  - templates/devices.html
  - PROJECT_STATE.md
- Summary of changes:
  - Added a frontend-only Connectivity Matrix subsection under System Checks on the Devices page
  - Rendered `connectivity`, `connectivity_summary`, and `connectivity_note` without changing existing system-check or detected-systems render flows
  - Added resilient empty, all-skipped, and error-state handling for connectivity responses
### Last Update
- Feature: Evidence harvesting and fingerprint storage foundation
- Files modified:
  - app.py
  - checks/validation.py
  - data/fingerprints.json
  - PROJECT_STATE.md
- Summary of changes:
  - Added per-device `evidence` blocks to validation results, including observed ports, summarized HTTP evidence, vendor, MAC, services, and fingerprint details
  - Added JSON-backed fingerprint persistence in `data/fingerprints.json` with `load_fingerprints()`, `save_fingerprints()`, and `merge_fingerprint()` helpers
  - Wired `validate_all` and `validate_systems` to merge observed device evidence over time using MAC as the preferred key and IP as fallback
  - Merge behavior preserves stronger type/fingerprint data, unions ports/services, accumulates HTTP headers, and updates `last_seen`
### Last Update
- Feature: Evidence collection and fingerprint merge correctness fix
- Files modified:
  - app.py
  - checks/validation.py
  - PROJECT_STATE.md
- Summary of changes:
  - Fixed `run_validation_for_all()` to preserve input device order so validate-all/system fingerprint persistence no longer cross-pairs results between devices
  - Ensured validation evidence uses the same observed validation result data path, including extracted open ports and HTTP summary data
  - Hardened fingerprint merging with deep-copy behavior and key/IP guards so stored records keep the correct device identity and `evidence.ip`
### Last Update
- Feature: Diagnostics discovery UI responsiveness and state handling improvements
- Files modified:
  - templates/diagnostics.html
  - PROJECT_STATE.md
- Summary of changes:
  - Tightened diagnostics discovery UI state transitions for idle, scanning, completed-with-results, completed-without-results, and failure cases
  - Ensured discovery results always refresh from the latest backend response and that loading/button states clear reliably after completion, cancellation, or error
  - Improved Add All Discovered feedback to use the latest discovered result set and show clearer visible status messaging
### Last Update
- Feature: Progressive diagnostics host discovery jobs
- Files modified:
  - app.py
  - templates/diagnostics.html
  - PROJECT_STATE.md
- Summary of changes:
  - Diagnostics discovery now starts an in-memory backend job and polls status so discovered hosts appear progressively instead of only after the full scan completes
  - Added visible running, completion, failure, and cancellation state messaging so long-running diagnostics actions do not feel frozen
  - Preserved the existing one-shot discovery endpoint for compatibility with current discovery/add/fingerprinting flows


### Last Update
- Feature: Reusable background job model for long-running tasks
- Files modified:
  - app.py
  - PROJECT_STATE.md
- Summary of changes:
  - Refactored in-memory job handling into a small reusable background job pattern with shared creation, lookup, update, and cancellation helpers
  - Discovery is now the first implementation of the shared job model without changing its current endpoints or progressive UX behavior
  - Future long-running actions should reuse the same job pattern so visible status and partial results stay consistent
### Last Update
- Feature: Conservative live-network evidence capture groundwork
- Files modified:
  - app.py
  - data/device_evidence.json
  - PROJECT_STATE.md
- Summary of changes:
  - Added a readable JSON-backed evidence store at data/device_evidence.json with reusable record_device_observation(...) helper logic
  - Discovery, fingerprint_host, validate_device, validate_all, and validate_systems now record live observed device evidence including identity, hostnames, ports, HTTP summary, and platform/type hints
  - Learning remains conservative and explainable: evidence accumulates without weak learned guesses silently overriding saved device truth