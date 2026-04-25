# NetPi Project State## System OverviewNetPi is a Raspberry Pi-based AV network commissioning tool.- Flask backend (app.py)- nginx reverse proxy at /tools- Web UI in templates/diagnostics.html---## Core Capabilities (WORKING)### Network Discovery- VLAN-aware subnet selection- Host discovery via nmap (-sn)- Hostname resolution:  - reverse DNS  - mDNS (avahi)### Device Identification- MAC address extraction- Vendor lookup- Vendor → device type inference (guess_type_from_vendor)### Fingerprinting- Targeted nmap port scan- Expanded AV-aware port list- Multi-layer classification:  1. Port-based detection  2. Vendor refinement  3. Combined logic- Runs automatically in background (UI)- Updates “Likely type” dynamically---## Device Management### Bulk Add (NEW)- Select multiple discovered devices- Sends:  - IP  - hostname  - VLAN  - type (fingerprint/vendor derived)  - MAC  - vendor### Single Add- Per-device add button- Uses fingerprint result### Auto Naming (NEW)Backend naming system:- display → LCD-##- projector → PJ-##- camera → CAM-##- network-device → SW-##- crestron / control → CP-##- qsys / biamp / shure / dante → DSP-##- novastar → VX-##- lighting (artnet/sacn/grandma) → LGT-##- printer → PRN-##- fallback → DEV-##Handled by:- device_name_prefix()- generate_device_name()---## UI Features### Toolbar (UPDATED)- Left:  - VLAN select  - Run Checks  - Discover Hosts  - Cancel Discovery (AbortController)- Right:  - Add Selected (bulk add)  - Export CSV  - Open Report  - Manage Devices### Discovery Table- Checkbox selection- Hostname / IP / MAC / Vendor- Status badge- Likely type:  - initial vendor guess  - updated via fingerprinting- Actions:  - Quick port scan  - Add to devices### Background Behavior- Discovery is async- Fingerprinting runs per device- Cancel button aborts frontend request---## Important Backend Functions- guess_type_from_vendor()- fingerprint_host()- add_bulk_devices()- add_discovered_device()- generate_device_name()- device_name_prefix()---## Known Constraints / Rules- Do NOT rewrite working fingerprint_host()- Do NOT break add_bulk_devices()- Do NOT remove background fingerprinting- Prefer extending logic instead of replacing- Keep changes incremental and testable---## Current Architecture StrengthNetPi now operates as a **2-stage intelligence system**:1. Fast classification (vendor/MAC)2. Accurate refinement (port fingerprinting)This mimics professional network discovery tools.---## Next Feature (IN PROGRESS)Paste-based device import:- Paste Excel (tab-separated) data- Auto-detect headers:  - Name, IP, VLAN, Type, MAC, Vendor, Notes- Validate IPs- Infer missing type- Auto-name missing names- Preview before import- Bulk add using existing system- Skip duplicates---## Chat Continuity Instruction (IMPORTANT)When continuing in a new chat:- Treat this file as the **source of truth**- Do NOT rebuild existing features- Only extend functionalityBefore making changes:1. Read this state2. Ask for missing context if unsure3. Apply minimal, surgical edits---## Auto-Update InstructionAfter each completed feature, append:### Last Update- Feature:- Files modified:- Summary of changes:The assistant should always:- Update this section- Keep the document current- Avoid duplicating existing functionality### Last Update- Feature: Paste-based device import (Devices page integration)- Files modified:  - app.py  - templates/devices.html- Summary of changes:  - Implemented Excel-style paste import system  - Added backend parsing with header detection and validation  - Added preview API with duplicate and invalid row detection  - Integrated paste workflow into Devices page UI  - Added preview → add → save workflow using existing deviceList system  - Ensured compatibility with existing saveDevices() logic  - Preserved all existing discovery and fingerprinting functionality---## API Testing Rules- ALWAYS use curl for testing endpoints when possible- Prefer curl over browser testing for debugging- Always provide exact curl commands ready to paste- Use jq for readable output when appropriate---## Safe Editing Rules- ALWAYS inspect files with grep or sed before modifying- NEVER assume exact code blocks exist- Match and replace only verified text- If a patch fails, stop and re-check structure- Prefer incremental inserts over replacements---## Deep Validation GoalsValidation should evolve beyond simple checks:### Network Intelligence- Identify open TCP ports per device- Track accessible services (HTTP, HTTPS, SSH, etc.)- Record latency and responsiveness### Service Awareness- HTTP title extraction- SSL detection- API endpoint reachability (future)### Output Structure ExpansionValidation results should include:- open_ports: [80, 443]- service_map: {80: "http", 443: "https"}- latency_ms- check_details### Long-Term DirectionNetPi should function as:- Lightweight AV-aware scanner- Deployment validation engine- Commissioning verification tool---## Debugging Standard (MANDATORY)- ALWAYS use curl-first debugging for backend endpoints- NEVER rely on browser testing when debugging APIs- ALWAYS provide curl commands BEFORE suggesting code changes- ALWAYS verify endpoint responses with curl before UI debugging---## Pre-Edit Inspection Protocol (MANDATORY)Before modifying ANY file:1. Run grep to confirm code location2. Verify exact strings exist3. If not found → STOP and reassess4. Only patch confirmed textThis prevents breaking working UI or backend logic.---## Validation Output Contract (STRICT)All validation results should follow this structure:{  "ip": "192.168.1.20",  "name": "DSP-01",  "type": "qsys",  "overall": "pass|fail|warn",  "latency_ms": number,  "open_ports": [80, 443],  "service_map": {    "80": "http",    "443": "https"  },  "results": [    {      "check": "ping|port:80|http",      "status": "pass|fail|warn",      "detail": "string"    }  ]}Rules:- open_ports must be derived automatically- service_map must be inferred from ports- results must remain lightweight (fast checks only)- total validation time per device must stay under ~3 seconds## Cross-device system validationAdded backend cross-device readiness validation for AV systems.### New backend capability- `run_system_validation(devices)` in `checks/validation.py`- New API endpoint: `POST /tools/api/validate_systems`### Current system validation rules- `crestron_control_to_qsys`  - checks whether a Crestron control processor and Q-SYS device both validate successfully  - requires target Q-SYS port `1710`- `crestron_control_to_biamp`  - checks whether a Crestron control processor and Biamp/Tesira device both validate successfully  - requires any of target ports `80`, `443`, or `23`- `crestron_uc_to_touchpanel`  - checks whether a Crestron UC engine and touch panel both validate successfully  - requires target ports `41795` and `443`### Important limitationThese are readiness / inference checks based on NetPi observations.They do **not** yet prove a source-initiated session from the actual AV endpoint itself.They are intended to answer:- "Does this system look ready?"- "Are expected services exposed?"- "Is the target side presenting the required ports?"### Prompting / workflow noteTreat `PROJECT_STATE.md` as source of truth.Always inspect files with `grep` before patching.Always use `curl` to test backend endpoints before UI work.Prefer small surgical patches over file rewrites.## NetPi V5 — Auto Device Typing + System Graph MappingDate: 2026-03-30### Completed in this session#### Auto device typing- Added safe auto-typing helper logic in `app.py`- Auto-typing uses:  - `observed_platform.platform`  - `fingerprint.platform`- Preference order:  1. `observed_platform`  2. `fingerprint`- Auto-promote only when confidence is strong- Conservative behavior:  - do not force type changes for weak/unknown matches  - only apply when current type is weak/mismatched and confidence is high- Added `auto_type` object to per-device validation response from:  - `POST /tools/api/validate_device`#### Auto-type apply endpoint- Added:  - `POST /tools/api/auto_type_devices`- Endpoint runs validation per device and safely updates device types when strong matches exist- Confirmed working:  - `DEV-02` auto-promoted from `web-device` to `qsys`#### Devices file compatibility fix- Fixed `load_devices()` in `app.py`- `load_devices()` now supports both formats:  - legacy dict format: `{"devices": [...]}`  - flat list format: `[...]`- Prevents crashes when `devices.json` is a top-level list#### System graph backend- Added system graph builder in `app.py`- `build_detected_systems(devices, system_results)` now returns:  - `systems`  - `mode`  - `edge_count`- Added relationship model:  - `from`  - `to`  - `type`  - `source_check`  - `inferred`- Graph currently supports:  - real rule-based edges when source/target pairs exist  - inferred fallback edges when only grouped peers exist#### Current system graph behavior- Current `validate_systems` output includes:  - `detected_systems`- Current mode observed:  - `type_grouping`- Current inferred graph result observed:  - `NV21-01 -> DEV-02 (peer)`- Current fallback behavior:  - if no real system-rule edges exist, graph builder groups compatible AV device types and creates inferred `peer` relationships#### UI — Detected Systems panel- Added Detected Systems section to `templates/devices.html`- Added `renderDetectedSystems(data)` function- Hooked Detected Systems rendering into:  - `runSystemValidation()`- UI now displays:  - detected system id  - summary chain  - device list  - relationship rows  - relationship badge (`peer`)  - inferred marker when applicable### Current known state- Working:  - per-device validation  - validate all  - system validation  - auto-type response in validate_device  - auto-type bulk apply endpoint  - detected systems backend response  - detected systems frontend panel- Current graph is still mostly fallback/inferred because system validation rules are skipping when required typed devices are not yet present- Existing system validation rules in `checks/validation.py` remain:  - `crestron_control_to_qsys`  - `crestron_control_to_biamp`  - `crestron_uc_to_touchpanel`### Important implementation notes- `PROJECT_STATE.md` remains the single source of truth- Do not rewrite working features- Do not break:  - `renderTable()`  - pasted-device import parser  - existing validation endpoints  - working System Checks panel- Prefer grep-first inspection and surgical patches- Always test backend endpoints with `curl` before UI work- Safe patching was required because several exact-text anchors in `devices.html` differed from expected formatting### Best next stepImprove strong auto-typing for real AV roles so system-rule graph edges can become real instead of inferred.Priority targets:1. Crestron control processors2. Crestron touch panels3. Crestron UC engines4. Biamp / Tesira devicesDesired outcome of next step:- More accurate device roles in `devices.json`- `run_system_validation()` begins producing real `from_device` / `to_device` pairs- `detected_systems.mode` shifts from fallback `type_grouping` toward real graph relationships- UI displays relationships such as:  - `CP-01 -> DSP-01 (control)`  - `DSP-01 -> TP-01 (ui)`### Endpoint reminders- Per-device validation:  - `POST /tools/api/validate_device`- Bulk validation:  - `POST /tools/api/validate_all`- System validation:  - `POST /tools/api/validate_systems`- Auto-type apply:  - `POST /tools/api/auto_type_devices`### Current observed example- Auto-typing successfully changed:  - `DEV-02`: `web-device` -> `qsys`- Current detected systems example:  - `NV21-01 -> DEV-02 (peer)`## NetPi Development Workflow Standard (Persistent)This section defines how ChatGPT should respond in ALL future NetPi chats.### Core behavior rules (DO NOT REPEAT IN FUTURE CHATS)- Treat PROJECT_STATE.md as the single source of truth- Do not restate these rules in future chats- Assume these rules are already known and active### Development principles- NEVER rewrite working features- ALWAYS apply small, surgical patches- ALWAYS inspect files with grep before modifying- ALWAYS verify backend with curl before touching UI- NEVER break:  - renderTable()  - pasted-device parser  - existing API endpoints- Prefer safe patch scripts over inline editing- Avoid fragile string matching when possible---## Command-Driven Workflow Mode (Default)All future responses should follow this structure:### 1. INSPECTProvide exact commands:- grep- nl- sed -n### 2. PATCHProvide:- backup command- safe patch script (python or sed)- exact insertion/replacement logic### 3. RESTARTAlways include:sudo systemctl restart netpisudo systemctl restart nginx### 4. VERIFY (MANDATORY)Always include curl:curl -s -X POST http://127.0.0.1/tools/api/<endpoint> | jq .### 5. EXPECTED RESULTExplain what should change:- backend response- UI behavior (if applicable)### 6. NO FLUFF- No long explanations unless requested- Focus on execution---## Expanded AV Role Inference TargetsPriority device role detection MUST include:### Core AV roles1. Crestron control processors2. Crestron touch panels3. Crestron UC engines4. Biamp / Tesira devices### Q-SYS ecosystem (NEW PRIORITY)5. Q-SYS Core (DSP)6. Q-SYS NV endpoints:   - NV-21   - NV-32-H7. Q-SYS Touch Panels (TSC series)8. Q-SYS peripherals (QIO, etc.)### Detection expectations- Use:  - observed ports  - fingerprint platform  - known service ports- Prefer HIGH CONFIDENCE promotion only- Avoid false positives---## Target System Graph EvolutionCurrent:- mode: type_grouping- inferred peer edgesTarget:- mode: graph- real edges:  - crestron_control -> qsys_core  - qsys_core -> touchpanel  - uc_engine -> touchpanel  - qsys_nv -> qsys_core---## Instruction to Future ChatsDO NOT re-ask for:- workflow structure- patch style- command formatASSUME:- command-driven workflow is required- safe patching is required- curl verification is required### Last Update- Feature: System validation backed by target port evidence for Q-SYS Core to NV relationships- Files modified:  - checks/validation.py  - PROJECT_STATE.md- Summary of changes:  - Added lightweight system-rule target port evidence collection using existing TCP probing helper  - Populated `required_target_ports`, `observed_target_ports`, and `target_open_ports` for Q-SYS Core to NV checks  - Switched system rule pass/fail to use observed network evidence instead of broad device `overall` validation status### Last Update- Feature: Stricter Q-SYS inference and clearer system skip messaging- Files modified:  - app.py  - checks/validation.py  - PROJECT_STATE.md- Summary of changes:  - Tightened Q-SYS role inference so generic web devices are no longer treated as Q-SYS from weak signals alone  - Prevented low-confidence Q-SYS fingerprint fallback from reinforcing stale or weak auto-typing  - Improved system validation skip reasons with Q-SYS-specific missing-device messages### Last Update- Feature: Removed legacy generic Q-SYS touchpanel rule- Files modified:  - app.py  - checks/validation.py  - PROJECT_STATE.md- Summary of changes:  - Removed the older `qsys_to_touchpanel` system rule so Q-SYS messaging now follows the stricter `qsys-core` to `qsys-touchpanel` model  - Dropped the stale graph label mapping tied to the removed generic Q-SYS touchpanel rule### Last Update- Feature: Suppressed weak fallback type grouping for single-role AV evidence- Files modified:  - app.py  - PROJECT_STATE.md- Summary of changes:  - Updated fallback detected-system grouping to return no inferred systems when only one AV role is present  - Preserved the `detected_systems` output shape while reducing noisy peer groupings from incomplete role evidence### Last Update- Feature: Diagnostics discovery bulk-add cleanup- Files modified:  - app.py  - templates/diagnostics.html  - PROJECT_STATE.md- Summary of changes:  - Removed the pasted-device import UI from diagnostics only and left the Devices page import workflow unchanged  - Added diagnostics-side `Add All Discovered` action backed by a new `/tools/api/devices/add_all_discovered` endpoint  - Reused shared discovered-device add logic so duplicate IPs are skipped and bulk add returns `added`, `skipped_existing`, and `total_seen`### Last Update- Feature: Diagnostics post-add fingerprint follow-up and per-row VLAN editing- Files modified:  - app.py  - templates/diagnostics.html  - templates/devices.html  - PROJECT_STATE.md- Summary of changes:  - Extended `/tools/api/devices/add_all_discovered` to return the newly added IP set for targeted follow-up actions without changing duplicate-skip behavior  - Added a diagnostics-side `Fingerprint Added Devices` action that only fingerprints the devices added by the last bulk add  - Made the Devices page VLAN cell editable per row while preserving the existing `deviceList` plus `saveDevices()` persistence flow into `devices.json`## Execution Boundaries  Local vs PiNetPi follows a strict separation between development environment and runtime environment.### Laptop (Windows / Dev Environment)- Used for:  - Code editing  - Planning  - Static analysis  - Syntax checks (e.g. python -m py_compile app.py)- NOT used for:  - Running NetPi backend endpoints  - curl testing against /tools/api/*  - Any network validation or discovery logic### Raspberry Pi (Runtime / Source of Truth for Execution)- The ONLY environment where:  - Flask app is running  - nginx is serving /tools  - devices.json is live  - Network discovery and fingerprinting are valid### Critical Rule- NEVER run curl or endpoint tests from outside the Pi- NEVER assume localhost on dev machine == NetPi runtime### Required Testing PatternAll endpoint testing must be executed manually on the Pi using:curl -s http://127.0.0.1/tools/...### Codex / Assistant Behavior- Must NOT attempt to execute curl requests outside the sandbox- Must NOT simulate network results- Must ALWAYS provide:  1. Exact curl commands for Pi  2. Expected response shape  3. What success/failure looks like### Deployment Flow1. Edit code locally2. Syntax check locally (optional)3. Deploy to Pi4. Run curl tests on Pi5. Verify in browser via nginx (/tools)This separation is mandatory and must not be bypassed.### Last Update- Feature: Auto-assign VLAN from subnet on device add/import- Files modified:  - app.py  - templates/devices.html  - PROJECT_STATE.md- Summary of changes:  - Added backend CIDR-based VLAN inference with a default 10.110.50.0/24 -> AV_Control mapping  - Applied VLAN autofill only when incoming devices have no VLAN set across discovered-device add, add-all discovered, pasted import, preview, and save flows  - Updated Devices save handling so backend-normalized VLAN values are reflected in the UI after save without changing the existing table flow### Last Update- Feature: Settings-driven VLAN inference and read-only Devices VLAN UI- Files modified:  - app.py  - templates/devices.html  - PROJECT_STATE.md- Summary of changes:  - VLAN assignment is now inferred automatically from settings.json lans[].subnet using each VLAN ame as the saved label  - settings.json lans is now the sole source of truth for subnet-based VLAN mapping, with blank or unmatched subnets saving blank VLAN values  - Removed manual VLAN editing from the Devices UI while keeping VLAN visible and filterable as a read-only field### Last Update- Feature: Validate All repair and fingerprint type persistence- Files modified:  - app.py  - templates/diagnostics.html  - PROJECT_STATE.md- Summary of changes:  - Repaired the Devices page Validate All regression after the VLAN UI cleanup by restoring a valid backend response shape  - Fingerprinting now persists updated device types for matching saved devices when a weak stored type can be safely promoted to a stronger inferred type  - Diagnostics fingerprint follow-up now reports how many saved device type updates were written during the run### Last Update- Feature: guessed_type now follows fingerprint platform- Files modified:  - app.py  - PROJECT_STATE.md- Summary of changes:  - Updated /tools/api/fingerprint_host so guessed_type now derives from ingerprint.platform when a strong platform is identified  - Preserved the existing fallback guess logic for cases where fingerprint platform remains unknown  - Left the existing saved-device persistence logic unchanged so type promotion now works naturally once guessed_type is stronger### Last Update- Feature: fingerprint_host now uses rich validation fingerprinting- Files modified:  - app.py  - PROJECT_STATE.md- Summary of changes:  - Updated /tools/api/fingerprint_host to reuse the same un_validation() path as alidate_all, including HTTP title and observed platform evidence  - guessed_type now prefers the rich validation fingerprint and observed platform results before falling back to weak web-device style guesses  - Preserved the existing response shape and conservative saved-device type persistence behavior### Last Update- Feature: Connectivity matrix backend wired into validate_systems response- Files modified:  - app.py  - PROJECT_STATE.md- Summary of changes:  - Wired the Segment 1 connectivity evaluator into `POST /tools/api/validate_systems` without changing existing `results` or `detected_systems` response keys  - Added backend-only `connectivity`, `connectivity_summary`, and `connectivity_note` response fields  - Added failure-safe handling so connectivity matrix evaluation errors do not break base system validation output  - Deferred all UI rendering changes for a later segment### Last Update- Feature: Connectivity matrix UI rendering on Devices page- Files modified:  - templates/devices.html  - PROJECT_STATE.md- Summary of changes:  - Added a frontend-only Connectivity Matrix subsection under System Checks on the Devices page  - Rendered `connectivity`, `connectivity_summary`, and `connectivity_note` without changing existing system-check or detected-systems render flows  - Added resilient empty, all-skipped, and error-state handling for connectivity responses### Last Update- Feature: Evidence harvesting and fingerprint storage foundation- Files modified:  - app.py  - checks/validation.py  - data/fingerprints.json  - PROJECT_STATE.md- Summary of changes:  - Added per-device `evidence` blocks to validation results, including observed ports, summarized HTTP evidence, vendor, MAC, services, and fingerprint details  - Added JSON-backed fingerprint persistence in `data/fingerprints.json` with `load_fingerprints()`, `save_fingerprints()`, and `merge_fingerprint()` helpers  - Wired `validate_all` and `validate_systems` to merge observed device evidence over time using MAC as the preferred key and IP as fallback  - Merge behavior preserves stronger type/fingerprint data, unions ports/services, accumulates HTTP headers, and updates `last_seen`### Last Update- Feature: Evidence collection and fingerprint merge correctness fix- Files modified:  - app.py  - checks/validation.py  - PROJECT_STATE.md- Summary of changes:  - Fixed `run_validation_for_all()` to preserve input device order so validate-all/system fingerprint persistence no longer cross-pairs results between devices  - Ensured validation evidence uses the same observed validation result data path, including extracted open ports and HTTP summary data  - Hardened fingerprint merging with deep-copy behavior and key/IP guards so stored records keep the correct device identity and `evidence.ip`### Last Update- Feature: Diagnostics discovery UI responsiveness and state handling improvements- Files modified:  - templates/diagnostics.html  - PROJECT_STATE.md- Summary of changes:  - Tightened diagnostics discovery UI state transitions for idle, scanning, completed-with-results, completed-without-results, and failure cases  - Ensured discovery results always refresh from the latest backend response and that loading/button states clear reliably after completion, cancellation, or error  - Improved Add All Discovered feedback to use the latest discovered result set and show clearer visible status messaging### Last Update- Feature: Progressive diagnostics host discovery jobs- Files modified:  - app.py  - templates/diagnostics.html  - PROJECT_STATE.md- Summary of changes:  - Diagnostics discovery now starts an in-memory backend job and polls status so discovered hosts appear progressively instead of only after the full scan completes  - Added visible running, completion, failure, and cancellation state messaging so long-running diagnostics actions do not feel frozen  - Preserved the existing one-shot discovery endpoint for compatibility with current discovery/add/fingerprinting flows### Last Update- Feature: Reusable background job model for long-running tasks- Files modified:  - app.py  - PROJECT_STATE.md- Summary of changes:  - Refactored in-memory job handling into a small reusable background job pattern with shared creation, lookup, update, and cancellation helpers  - Discovery is now the first implementation of the shared job model without changing its current endpoints or progressive UX behavior  - Future long-running actions should reuse the same job pattern so visible status and partial results stay consistent### Last Update- Feature: Conservative live-network evidence capture groundwork- Files modified:  - app.py  - data/device_evidence.json  - PROJECT_STATE.md- Summary of changes:  - Added a readable JSON-backed evidence store at data/device_evidence.json with reusable record_device_observation(...) helper logic  - Discovery, fingerprint_host, validate_device, validate_all, and validate_systems now record live observed device evidence including identity, hostnames, ports, HTTP summary, and platform/type hints  - Learning remains conservative and explainable: evidence accumulates without weak learned guesses silently overriding saved device truth### Last Update- Feature: Confidence-scored suggested device types from learned evidence- Files modified:  - app.py  - templates/devices.html  - templates/diagnostics.html  - PROJECT_STATE.md- Summary of changes:  - Added conservative confidence-scored type suggestions backed by current validation plus stored learned evidence  - Surfaced suggested_type, confidence_score, confidence_label, and suggestion_reasons in safe backend responses without changing existing fields  - Explicit saved device truth still outranks learned suggestions, while weak buckets like generic/web-device/linux-web-device can now surface stronger advisory suggestions### Last Update- Feature: Stage 4.5 AV vendor fingerprint enrichment- Files modified:  - app.py  - checks/validation.py  - PROJECT_STATE.md- Summary of changes:  - Added lightweight HTTP keyword and SSH banner evidence capture, reusing existing evidence objects without changing the conservative application model  - Added Biamp/Tesira and Barco fingerprint signals plus repeated-evidence reinforcement to improve AV suggestion coverage  - Preserved advisory-only suggestion behavior so explicit device truth still wins and weak devices do not get unsafe type upgrades### Last Update- Feature: Stage 4.5a Biamp hostname scoring tune- Files modified:  - app.py  - PROJECT_STATE.md- Summary of changes:  - Tuned Biamp hostname scoring so clear BIAMP-* devices can surface advisory biamp-tesira suggestions  - Preserved conservative behavior for generic web and linux-web-device fingerprints without vendor markers### Last Update- Feature: Stage 4.6 stable device identity hardening- Files modified:  - app.py  - PROJECT_STATE.md- Summary of changes:  - Hardened evidence identity selection so MAC and stable hostname are preferred over IP where available  - Stale IP-only learning is less able to contaminate new device observations and advisory suggestions  - This improves safety before Stage 5 controlled suggestion application### Last Update- Feature: Stage 5 controlled application of high-confidence device suggestions- Files modified:  - app.py  - PROJECT_STATE.md- Summary of changes:  - Added controlled promotion for weak device types using existing suggestion scoring with a confidence threshold of 60  - Promotions are limited to safe weak-to-strong upgrades and do not overwrite strong existing types  - Added a backend apply_suggestions endpoint with traceable updated and skipped results without changing existing validation response shapes
### Last Update- Feature: Stage 6 expanded AV detection for unknown web devices- Files modified:  - app.py  - checks/validation.py  - PROJECT_STATE.md- Summary of changes:  - Added safe appliance-style detection for HTTP titles that explicitly identify a Video Wall Splicer  - Reused existing title/server evidence without inventing weak vendor matches for generic embedded web appliances  - Preserved existing Biamp and Crestron suggestion behavior while keeping openresty-only cases conservative### Last Update- Feature: Stage 6.5 AV detection library expansion- Files modified:  - app.py  - checks/validation.py  - PROJECT_STATE.md- Summary of changes:  - Added grouped AV detection helpers for Q-SYS, Biamp, Crestron, Barco, and generic video-processing devices using existing title, keyword, hostname, and port evidence  - Strengthened subtype classification for qsys-core, qsys-touchpanel, qsys-nv21, qsys-nv32, biamp-tesira, crestron_control, crestron_touchpanel, and video-wall-processor  - Preserved low false-positive constraints so weak embedded web evidence like openresty-only paths does not create reckless vendor-specific matches### Last Update- Feature: Stage 7 self-learning fingerprint library- Files modified:  - app.py  - PROJECT_STATE.md- Summary of changes:  - Added a lightweight self-learning fingerprint library layer that derives reusable device-class patterns from repeated strong evidence already stored in device evidence history  - Direct hardcoded detection rules remain in place, while repeated evidence can now safely reinforce reusable classes such as video-wall-processor, Q-SYS family roles, Biamp/Tesira, and Crestron roles  - Preserved Stage 6.6 identity safety and conservative behavior so weak unrelated devices, including openresty-only web devices, do not inherit risky learned classes### Last Update- Feature: Stage 7.5 signal-candidate fingerprint library bridge- Files modified:  - app.py  - PROJECT_STATE.md- Summary of changes:  - Repeated safe signal_candidates can now reinforce reusable fingerprint_library classes for approved AV families such as Biamp, Q-SYS, Crestron, and video-wall processors  - Promotion remains limited to repeated medium/high-strength signals and does not weaken Stage 6.6 identity safety or permit generic weak web evidence to invent risky classes### Last Update- Feature: Stage 7.6 effective_type for safe runtime type resolution- Files modified:  - app.py  - PROJECT_STATE.md- Summary of changes:  - Added an additive effective_type field so direct strong detections remain primary while strong safe learned suggestions can provide the best runtime type when direct evidence stays weak  - Preserved guessed_type, suggested_type, and existing safety checks without allowing learned evidence to override strong direct detections### Last Update- Feature: Stage 8 runtime AV system grouping- Files modified:  - app.py  - PROJECT_STATE.md- Summary of changes:  - Added a read-only build_runtime_system_groups(...) helper that clusters enriched devices into runtime AV systems using effective runtime types, VLAN affinity, and safe first-pass AV family pairings  - Wired POST /tools/api/validate_systems to return additive system_groups data before unchanged system validation execution  - Preserved existing validation, relationship inference, and persistence behavior by keeping grouping runtime-only and non-destructive### Last Update- Feature: Stage 8.1 runtime type conflict override- Files modified:  - app.py  - PROJECT_STATE.md- Summary of changes:  - Added a narrow runtime-only effective_type override when high-confidence fingerprint and observed platform evidence agree on the same detected platform, the suggested_type matches, and the saved strong type is from a different family  - Updated runtime resolution so effective_type and _resolved_type honor the same conflict override without writing to devices.json or changing apply_suggestions or fingerprint_host persistence  - Preserved conservative behavior for all other cases and kept validate_systems response shapes additive and unchanged
### Last Update
- Feature: Stage 9 system-aware validation from runtime system_groups
- Files modified:
  - app.py
  - PROJECT_STATE.md
- Summary of changes:
  - Added additive system_group_results output that maps flat run_system_validation(...) rows back onto runtime system_groups without changing the existing results array or validation engine
  - Grouped results include per-system device refs, types, confidence, and only the validation rows relevant to that runtime group, including conservative skipped-rule context where appropriate
  - Preserved runtime-only behavior with no devices.json writes, no fingerprint persistence changes, and no Stage 8 or 8.1 rollback


### Last Update
- Feature: Stage 10 topology-aware validation from stable system_group_results
- Files modified:
  - app.py
  - PROJECT_STATE.md
- Summary of changes:
  - Added additive topology_results output that classifies grouped validation rows by stable group membership as intra_group, cross_group, or unassigned
  - Preserved existing validate_systems fields and flat results while adding relation_classification and per-system topology counts
  - Kept runtime-only behavior with no devices.json writes and no persistence/fingerprint behavior changes

### Last Update
- Feature: Stage 10.1 fix topology classification membership lookup
- Files modified:
  - app.py
  - PROJECT_STATE.md
- Summary of changes:
  - Topology classification now resolves group membership by IP first and device name fallback when classifying validation rows
  - Added group lookup maps for ip->system_id and name->system_id and applied fallback to from_device/to_device when from_ip/to_ip are missing
  - Preserved topology_results schema and all existing validate_systems response fields without persistence changes

### Last Update
- Feature: Stage 10.2 classify group-scoped skipped topology rows as intra_group
- Files modified:
  - app.py
  - PROJECT_STATE.md
- Summary of changes:
  - Added a narrow topology fallback so unresolved skipped rows with group_relevance source/target/both are classified as intra_group inside their current system_group_results scope
  - Endpoint/device-name membership lookup remains first priority; fallback only runs when endpoint membership is unresolved
  - Preserved topology_results schema and all existing validate_systems fields without persistence changes
### Last Update
- Feature: Stage W0.3 command abstraction foundation
- Files modified:
  - app.py
  - command_helpers.py
  - PROJECT_STATE.md
- Summary of changes:
  - Added a tiny platform-aware command helper layer for ping, traceroute/tracert, and nmap command construction
  - Replaced duplicated inline command selection in diagnostics endpoints with helper calls while preserving subprocess behavior and response shapes
  - Kept Linux Pi behavior unchanged and retained Windows-compatible command selection for ping, tracert, and PATH-based nmap
### Last Update
- Feature: Stage W0.4 helper coverage for remaining OS-sensitive ping and discovery commands
- Files modified:
  - app.py
  - command_helpers.py
  - checks/devices.py
  - checks/network.py
  - checks/validation.py
  - PROJECT_STATE.md
- Summary of changes:
  - Extended the tiny command helper layer to cover validation-style ping commands and nmap host-discovery command construction
  - Replaced remaining inline Linux-only ping command construction in backend checks and validation paths with helper calls
  - Replaced inline discovery nmap command construction in app and network checks while preserving existing subprocess flow and response shapes
### Last Update
- Feature: Stage W0.8 Windows runtime readiness launch helpers and dependency manifest
- Files modified:
  - requirements.txt
  - start_netpi.ps1
  - run_netpi.bat
  - PROJECT_STATE.md
- Summary of changes:
  - Added a minimal requirements.txt based on current NetPi third-party imports
  - Added a simple PowerShell launch script for Windows operators that starts app.py from the repo directory and prints the local tools URL
  - Added a trivial batch launcher for Windows environments where double-click or cmd.exe startup is preferred
### Last Update
- Feature: W6.1 requirements generation endpoint (config-driven baseline)
- Files modified:
  - app.py
  - checks/requirements.py
  - configs/type_requirements.json
  - PROJECT_STATE.md
- Summary of changes:
  - Added new POST `/tools/api/generate_requirements` endpoint that generates per-device requirement rows from inventory using runtime type resolution priority (`effective_type` -> `_resolved_type` -> `suggested_type` -> persisted `type`)
  - Added lightweight requirements helper module for config loading, type normalization, and per-device requirement row generation
  - Added config-driven type-to-port/service mapping in `configs/type_requirements.json` with alias normalization and graceful unmapped handling
  - Preserved existing endpoint response shapes and existing UI/backend behavior

### Last Update
- Feature: W6.2 Requirements screen live wiring and requirements awareness badge integration
- Files modified:
  - templates/requirements.html
  - templates/devices.html
  - PROJECT_STATE.md
- Summary of changes:
  - Wired Requirements page to live `POST /tools/api/generate_requirements` and removed fake static requirement rows from normal rendering
  - Added loading/empty/error states, live summary cards, per-device derivation visibility (`effective_type`, `source_type`, `derived_from`), and safe unmapped device rendering
  - Added lightweight requirements state cache in localStorage (`netpi.requirements.state.v1`) shared across pages so Devices intelligence drawer now shows real requirements availability (`Available`/`Missing`/`Unknown`) from live generation data
### Last Update
- Feature: W6.3 flow mapping endpoint from system validation relationships
- Files modified:
  - app.py
  - checks/flows.py
  - PROJECT_STATE.md
- Summary of changes:
  - Added new POST `/tools/api/generate_flows` endpoint that derives device-to-device flow rows from runtime-enriched inventory using `run_system_validation(...)`, connectivity validation outputs, and runtime system-group membership
  - Added lightweight `checks/flows.py` helpers for relationship-to-flow expansion, category normalization, confidence scoring, flow id construction, and safe unmapped relationship capture
  - Endpoint returns stable `ok/count/summary/results/unmapped_relationships` shape with per-flow source/destination/protocol/port/purpose/derived_from/system_id fields and keeps ambiguous or skipped relationships in unmapped output without failing
### Last Update
- Feature: W6.4 system requirements aggregation endpoint
- Files modified:
  - app.py
  - checks/system_requirements.py
  - PROJECT_STATE.md
- Summary of changes:
  - Added new POST `/tools/api/system_requirements` endpoint that aggregates W6.3 flow rows into system-level intent grouped by category (`control`, `media`, `service`, `management`, `unknown`)
  - Added lightweight `checks/system_requirements.py` helpers to merge flow rows by system/category/source-destination/protocol/direction/purpose, roll up ports, and preserve derivation traceability
  - Endpoint preserves safe handling for unresolved inputs by returning non-fatal `ungrouped_flows` and supports optional direct `flows` payload for test/debug scenarios
### Last Update
- Feature: W7.0 firewall plan generation endpoint
- Files modified:
  - app.py
  - PROJECT_STATE.md
- Summary of changes:
  - Added new POST `/tools/api/generate_firewall_plan` endpoint that transforms system-level requirements into an IT-ready firewall rule table with deterministic ordering and duplicate merging
  - Firewall rules now include required planning fields (`source_zone`, `destination_zone`, `protocol`, `port/ports`, `direction`, `purpose`, `business_justification`, `av_justification`, `confidence`) plus provenance (`source_systems`, devices, evidence)
  - Added required split between `min_required` and `recommended` rules and summary totals designed for future CSV/JSON export
  - Zone mapping uses requirement row VLAN/zone hints first, then settings-driven VLAN inference, with safe `Unknown`/`Unassigned` fallback labels when no trustworthy mapping is available
  - Confidence uses upstream values when present and conservative category defaults when missing; no persistence schema or existing endpoint shape changes were introduced
### Last Update
- Feature: W7.1 Firewall Plan screen live wiring
- Files modified:
  - templates/firewall.html
  - PROJECT_STATE.md
- Summary of changes:
  - Wired `templates/firewall.html` to live `POST /tools/api/generate_firewall_plan` and removed static/demo rule datasets
  - Live table rendering now uses backend `firewall_plan.rules` with visible per-row `requirement_level` (`min_required` / `recommended`) and split section counts
  - Filter bar is wired to live data for source zone, destination zone, system, and criticality with combined filtering and clean empty states
  - CSV/JSON exports are wired to currently visible filtered rows with deterministic flattened fields for handover output
### Last Update
- Feature: W7.2 IP Schedule export wiring
- Files modified:
  - app.py
  - templates/ipschedule.html
  - PROJECT_STATE.md
- Summary of changes:
  - Added additive `GET /tools/api/ipschedule` endpoint that exposes current inventory rows from `load_devices()` with freshness view fields for schedule rendering
  - Wired `templates/ipschedule.html` to live inventory data and removed static/demo rows and export stubs
  - Enabled missing metadata highlighting for critical and advisory fields, plus truthful manual override markers when explicit manual signals are present
  - Enabled deterministic CSV export (`<project>-ip-schedule.csv`) using current visible schedule rows with Excel-safe quoting
### Last Update
- Feature: W7.3 Validation screen wiring
- Files modified:
  - templates/validation.html
  - PROJECT_STATE.md
- Summary of changes:
  - Wired validation screen to real `POST /tools/api/validate_all` and `POST /tools/api/validate_systems` endpoints and removed static/demo validation rows
  - Implemented Live / Logical / Restricted modes with distinct data paths (Logical uses system-oriented validation only; Restricted scopes validation using configured VLAN when available)
  - Populated by-system, by-flow, and by-device tabs from truthful backend response fields with safe empty/error handling
  - Added deterministic per-row recommended actions derived from status and validation context while preserving existing Devices page validation behavior
### Last Update
- Feature: W7.4 Dashboard wiring
- Files modified:
  - app.py
  - templates/base.html
  - templates/dashboard.html
  - PROJECT_STATE.md
- Summary of changes:
  - Added additive `/tools/dashboard` page route and sidebar navigation entry without changing existing screen routes
  - Wired dashboard summary cards to live app data from existing endpoints (`/tools/api/ipschedule`, `/tools/api/validate_all`, `/tools/api/validate_systems`, `/tools/api/system_requirements`, `/tools/api/generate_firewall_plan`)
  - Added live attention panels for missing metadata, low-confidence device types, and validation/flow concerns using conservative derivation from truthful existing fields
  - Added real quick-action links to Devices, Validation, Firewall Plan, and IP Schedule with partial-failure-safe dashboard rendering
### Last Update
- Feature: W8.0 Recommendations engine endpoint
- Files modified:
  - app.py
  - PROJECT_STATE.md
- Summary of changes:
  - Added new POST `/tools/api/recommendations` endpoint that generates consultant-style recommendation rows from existing validation, system, requirements, firewall, and device evidence paths
  - Implemented deterministic category/severity mapping, deduplication, stable ordering, and summary grouping (`by_severity`, `by_category`) for UI/report compatibility
  - Added explicit AV-focused recommendation template coverage for Dante segmentation/multicast, DHCP reservations, VLAN fragmentation, unvalidated control ports, Barco advisory handling, control relationship concerns, low-confidence types, metadata gaps, and security exposure
  - Endpoint accepts wrapper payload inputs or empty payload fallback and keeps evidence traceability via `evidence_source` and `affected_devices` fields
### Last Update
- Feature: W8.1 Recommendations screen wiring
- Files modified:
  - templates/recommendations.html
  - PROJECT_STATE.md
- Summary of changes:
  - Wired recommendations screen to live `POST /tools/api/recommendations` data and removed static/demo recommendation content
  - Implemented category-first recommendation grouping (`integrity`, `design`, `segmentation`, `DHCP`, `multicast`, `security`, `commissioning_readiness`) with deterministic ordering
  - Added severity badge rendering from backend values and live summary card counts
  - Added evidence source links mapped to relevant existing working screens plus affected-device context rendering
### Last Update
- Feature: W8.2 Explain-the-Reason trust layer
- Files modified:
  - templates/devices.html
  - templates/requirements.html
  - templates/firewall.html
  - templates/recommendations.html
  - PROJECT_STATE.md
- Summary of changes:
  - Added lightweight, click-safe `Why ...?` explanation toggles across key output screens to expose reasoning without cluttering default views
  - Devices now exposes concise type-inference rationale in the intelligence drawer using confidence, derived-from context, evidence summary, and suggestion reasons when available
  - Requirements now includes a derivation explanation block per expanded row to clarify why protocol/port/service requirements were generated
  - Firewall rows now include `Why this rule?` explanation details based on purpose, business/AV justification, and evidence with truthful limited-evidence fallback
  - Recommendations cards now keep suggested action visible while moving finding/impact/evidence context into a consistent `Why this recommendation?` details panel
### Last Update
- Feature: W8.3 Full report generation
- Files modified:
  - app.py
  - templates/report.html
  - templates/dashboard.html
  - PROJECT_STATE.md
- Summary of changes:
  - Added additive `POST /tools/api/generate_report` endpoint that aggregates validation, requirements, firewall plan, IP schedule, and recommendations into one structured report payload
  - Added additive `/tools/report` route that renders the same aggregated report as printable PDF-ready HTML for browser print/save workflows
  - Report output includes `report.summary`, `report.sections`, and `report.html` (full render string) to support both machine-readable and presentation-ready usage
  - Added a Dashboard quick action (`Build Final Report`) linking directly to the live report view
### Last Update
- Feature: W6.06 Passive MAC harvest during validation
- Files modified:
  - app.py
  - checks/validation.py
  - command_helpers.py
  - PROJECT_STATE.md
- Summary of changes:
  - Added passive, best-effort MAC resolution helper flow with lookup priority `ARP cache -> SNMP context (if already present) -> LLDP/CDP context (if already present)`
  - Integrated MAC enrichment into `POST /tools/api/validate_device` without changing core validation flow or introducing blocking scan stages
  - Added safe write-back behavior to inventory records (`mac`, additive `mac_address`, `mac_source`) while preventing overwrite of known-good MAC values with blank/invalid results
  - On unresolved lookup with no known MAC, writes `mac_address: null` and `mac_source: "unknown"` and keeps validation success response non-blocking
### Last Update
- Feature: W6.07 MAC source attribution in device record
- Files modified:
  - app.py
  - checks/validation.py
  - templates/devices.html
  - PROJECT_STATE.md
- Summary of changes:
  - Aligned canonical `mac_source` contract to `arp-cache`, `snmp-oid`, `lldp`, `user-entered`, and `unknown` with backward-safe normalization of legacy/internal labels
  - Updated `validate_device` persistence/response handling to normalize source labels while preserving valid existing MAC values and non-blocking enrichment behavior
  - Added save-path handling so explicit user MAC edits persist with `mac_source: user-entered` when no stronger machine-confirmed source is present
  - Device detail drawer now shows MAC provenance in-line (for example `MAC (arp-cache): AA:BB:CC:DD:EE:FF`) and missing-metadata MAC checks use normalized MAC validity

### Last Update
- Feature: W6.08 MAC conflict detection + cross-workflow MAC persistence
- Files modified:
  - app.py
  - templates/devices.html
  - templates/diagnostics.html
  - PROJECT_STATE.md
- Summary of changes:
  - Added inventory-wide duplicate MAC detection in the shared save-normalization path and persist `mac_conflict: true` on all records sharing the same normalized MAC (`false` otherwise)
  - Extended MAC persistence from discovery/scan/add-discovered workflows using canonical source mapping and non-blocking best-effort write-back (`arp-cache` when learned from discovery output)
  - Added a dedicated MAC column to Devices table plus conflict badge, while preserving existing detail-drawer provenance display
  - Diagnostics discovered-host state is now cached and restored so results remain visible until a new discovery run replaces them
  - Verified subnet/gateway fallbacks already default to `192.168.1.0/24` and `192.168.1.1` when settings do not provide explicit values

### Last Update
- Feature: Settings persistence hardening across restart/reboot
- Files modified:
  - app.py
  - PROJECT_STATE.md
- Summary of changes:
  - Hardened settings writes with temp-file flush/fsync plus replace to reduce partial-write/corruption risk during restart/crash windows
  - Added resilient settings load behavior with additive defaults, invalid-JSON recovery fallback, and one-time startup log messages for load source/recovery path
  - Preserved unknown/custom top-level settings keys and unknown per-VLAN keys during settings form saves to avoid destructive key loss
  - Added optional JSON save confirmation on POST /tools/settings when client requests application/json (`success`, `saved_to`, `timestamp`) while preserving existing HTML UI behavior

### Last Update
- Feature: W10.0 SNMP Enrichment Pass
- Files modified:
  - app.py
  - PROJECT_STATE.md
- Summary of changes:
  - Added lightweight best-effort SNMPv2c enrichment using configured project `snmp_community` when present, with short timeout/retry settings and safe optional-library fallback
  - Harvests `sysDescr`, `sysName`, `sysLocation`, `sysContact`, plus bounded interface name/description/MAC rows where available, writing additive `snmp_enriched` and `snmp_data` fields
  - Hooks enrichment into post-reachability validation, fingerprint, and discovered-device add flows so records become richer during or after discovery without changing reachability outcomes
  - Keeps SNMP passive/read-only and non-blocking in practice: silent skip when no community is configured, when SNMP is unsupported, or when a device does not answer

### Last Update
- Feature: W10.1 CDP / LLDP Neighbour Map
- Files modified:
  - app.py
  - templates/devices.html
  - PROJECT_STATE.md
- Summary of changes:
  - Added a dedicated topology artifact flow backed by `topology.json`, with safe load/save helpers plus additive `GET /tools/api/topology` and `POST /tools/api/topology/generate` routes
  - Topology generation queries known eligible switch-like inventory devices only, attempts LLDP first, and falls back to Cisco CDP only for Cisco-like switches when LLDP yields no usable rows
  - Generated rows remain compact and truthful (`switch`, `port`, neighbour hostname/IP/MAC, source protocol) with conservative inventory matching used only to improve displayed hostname where evidence is strong
  - Devices page now includes a read-only `Network Topology` inventory view with Generate/Refresh actions, while keeping discovery, validation, and existing UI flows non-blocking and unchanged

### Last Update
- Feature: W10.2 Multicast Group Discovery
- Files modified:
  - app.py
  - templates/validation.html
  - PROJECT_STATE.md
- Summary of changes:
  - Added a passive multicast artifact flow backed by `multicast_groups.json`, with safe load/save helpers plus additive `GET /tools/api/multicast_groups` and `POST /tools/api/multicast_groups/generate` routes
  - Multicast discovery reuses known eligible managed-switch selection, attempts passive IGMP membership discovery via SNMP only, and safely skips when SNMP or eligible switch infrastructure is unavailable
  - Saved rows remain compact and truthful (`group_address`, switch context, member count, and strong member IP/hostname correlation where available) without inventing subscriber lists when the switch MIB view is partial
  - Validation and recommendations now consume saved multicast findings additively, and the Validation page includes a read-only `Multicast Groups` panel for Generate/Refresh review without changing existing discovery or validation behavior
### Last Update
- Feature: W11.0 Project State Snapshot + Restore
- Files modified:
  - app.py
  - templates/settings.html
  - PROJECT_STATE.md
- Summary of changes:
  - Added additive `GET /tools/api/project/snapshot` to export a compressed portable `.avp` project archive with `manifest.json` including schema version, included files, missing optional files, source instance metadata, and notes
  - Added additive `POST /tools/api/project/restore` to validate archive structure/manifest/schema/paths/allowlist, create a timestamped pre-restore backup under `data/project_backups/`, and restore only approved state files with clear restored/skipped summary
  - Added minimal Settings page snapshot export link without introducing restore UI changes, preserving existing behavior and portability between Windows/Pi runtime instances
### Last Update
- Feature: W11.1 Snapshot Diff / Compare
- Files modified:
  - app.py
  - PROJECT_STATE.md
- Summary of changes:
  - Added additive read-only `POST /tools/api/project/snapshot/compare` endpoint to compare two `.avp` snapshots (`baseline` and `current`) with strict archive/manifest/schema/path/allowlist validation
  - Compare output reports compact devices/settings/topology/multicast/artifact differences (added/removed/changed) and summary counts without restoring or mutating local runtime state
  - Supports commissioning before/after and handoff audit workflows while preserving existing W11.0 snapshot/restore endpoint behavior
