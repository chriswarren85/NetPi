# NetPi Chapter 6 Canonical Data Contract (W6.0.5)

Status: Active planning contract for Chapter 6 wiring  
Scope: Canonical field language + source-priority mapping + observed type alias normalization  
Non-goal: No endpoint shape changes, no persistence schema changes, no UI rewrites

## 1) Canonical Objects

### 1.1 `device_identity`

Canonical fields:

- `id`
- `name`
- `ip`
- `mac`
- `vendor`
- `vlan`
- `notes`

Field meaning:

- `id`: stable key for joins and downstream references.
- `name`: operator-facing device label.
- `ip`: primary network address.
- `mac`: hardware identity when available.
- `vendor`: normalized vendor/manufacturer text.
- `vlan`: saved VLAN label from inventory/settings mapping.
- `notes`: operator context and handover notes.

Current source notes:

- Persisted `devices.json` is intentionally lean and may not include all optional metadata.
- Runtime enrichment does not replace persisted identity baseline.

Temporary `id` strategy (until explicit persisted ID exists):

1. `mac:<MAC>` when MAC exists and is usable.
2. `ip:<IP>` when MAC is missing.
3. `name:<NAME>` as final fallback (only if IP missing).

This follows current stable-identity behavior used in observation/fingerprint flows.

---

### 1.2 `runtime_typing`

Canonical fields:

- `effective_type`
- `source_type`
- `suggested_type`
- `confidence_score`
- `confidence_label`
- `reasoning_available`

Field meaning:

- `effective_type`: best runtime-resolved type for operational decisions.
- `source_type`: persisted/saved baseline type.
- `suggested_type`: advisory candidate type from suggestion logic.
- `confidence_score`: numeric strength for suggestion.
- `confidence_label`: bucketed confidence string.
- `reasoning_available`: `true` when suggestion reasoning exists (`type_suggestion`/`suggestion_reasons` present).

Resolution priority for `effective_type` consumption:

1. `effective_type`
2. `_resolved_type`
3. `suggested_type`
4. persisted `type` (`source_type`)

Notes:

- `effective_type`/`_resolved_type` are typically runtime-enriched, not guaranteed persisted.

---

### 1.3 `validation_summary`

Canonical fields:

- `overall`
- `pass_count`
- `warn_count`
- `fail_count`
- `check_count`
- `latency_ms`
- `validated_at`

Field meaning:

- `overall`: coarse validation result (`pass|warn|fail|error` depending on context).
- `pass_count`/`warn_count`/`fail_count`: derived status counts from `results[]`.
- `check_count`: total checks evaluated (`len(results)`).
- `latency_ms`: per-device validation elapsed metric when available.
- `validated_at`: runtime timestamp if captured by caller/context.

Current reality:

- `validate_all` and `validate_systems` do not provide one uniform top-level summary object for all consumers.
- Count fields should be derived from returned `results[]` where absent.

---

### 1.4 `connectivity_flow`

Canonical fields:

- `src_device`
- `src_ip`
- `dst_device`
- `dst_ip`
- `protocol`
- `port`
- `direction`
- `category`
- `purpose`
- `confidence`
- `derived_from`

Field meaning:

- `src_*`/`dst_*`: flow endpoints.
- `protocol`: transport/application protocol label.
- `port`: single normalized port for one flow row.
- `direction`: expected direction (default outbound from source when not explicit).
- `category`: connectivity family/category.
- `purpose`: operator-readable intent.
- `confidence`: inferred confidence bucket from status/evidence.
- `derived_from`: source object path/rule reference.

Normalization rule for `port`:

- If source contains multiple ports (`ports[]`), expand into one canonical flow row per port.

Current source mapping:

- Primary: `/tools/api/validate_systems` -> `connectivity[]` rows.
- Secondary: system rule rows from `results[]` when connectivity row unavailable.

---

### 1.5 `system_membership`

Canonical fields:

- `system_id`
- `device_count`
- `devices`
- `confidence`
- `types`
- `roles`

Field meaning:

- `system_id`: runtime system/group identifier.
- `device_count`: count of members.
- `devices`: normalized device refs for that system.
- `confidence`: grouping confidence.
- `types`: participating type set.
- `roles`: participating role set.

Current source mapping:

- Primary: `/tools/api/validate_systems` -> `system_groups[]`.
- Enriched relationship context: `system_group_results[]`, `topology_results[]`.

---

### 1.6 `handover_row`

Canonical fields:

- `name`
- `hostname`
- `ip`
- `mac`
- `serial`
- `vlan`
- `gateway`
- `dns`
- `vendor`
- `model`
- `type`
- `zone`
- `addressing_mode`
- `last_seen`
- `notes`
- `manual_override`

Field meaning:

- Structured handover/documentation row for IP schedule and client deliverables.

Current reality:

- Only subset is consistently persisted today (`name`, `ip`, `type`, `vlan`, `notes`, `mac`, `vendor` observed).
- `hostname`, `serial`, `gateway`, `dns`, `model`, `zone`, `addressing_mode`, `manual_override` are future/optional and may be null/blank.

Contract rule:

- Null/blank is valid and must be represented explicitly (incomplete is allowed; gaps visible).

---

## 2) Source Priority Map

### 2.1 `device_identity` source priority

1. Persisted inventory (`devices.json` via `load_devices()`).
2. Runtime enrichment overlays (non-persisted fields from enrich/validation).
3. Validation/evidence fallback only when persisted value absent.

### 2.2 `runtime_typing` source priority

1. Runtime validation-enriched row (`validate_all` result row or `enrich_device_runtime` output).
2. Runtime system-enriched row (`validate_systems` enriched device context).
3. Persisted `type`.

### 2.3 `validation_summary` source priority

1. Per-device validation row returned by `run_validation` path.
2. Derived counts from `results[]` where aggregate counts absent.
3. UI fallback derivation only when summary object missing.

### 2.4 `connectivity_flow` source priority

1. `/tools/api/validate_systems` -> `connectivity[]`.
2. `/tools/api/validate_systems` -> `results[]` (system rule rows).
3. Derived placeholders are allowed only when both are absent.

### 2.5 `system_membership` source priority

1. `/tools/api/validate_systems` -> `system_groups[]`.
2. `system_group_results[]` and `topology_results[]` for classification context.
3. `detected_systems` graph fallback for display/relationship hints.

### 2.6 `handover_row` source priority

1. Persisted inventory baseline.
2. Runtime enrichment fields (typing/freshness/validation context).
3. Manual operator overrides.
4. Null/blank placeholders (explicitly allowed).

---

## 3) Observed Type Alias Normalization

Use normalized canonical tokens internally while accepting existing observed variants.

### 3.1 Crestron family

- Canonical target: `crestron-processor`
  - Variants: `crestron_control`, `crestron-control`, `crestron_processor`, `crestron`, `crestron-processor`
- Canonical target: `crestron-touchpanel`
  - Variants: `crestron_touchpanel`, `touchpanel`, `tp1070`, `crestron-touchpanel`
- Canonical target: `crestron-uc-engine`
  - Variants: `crestron_uc`, `crestron-uc`, `uc-engine`, `uc_engine`, `crestron-uc-engine`

### 3.2 Q-SYS family

- Canonical target: `qsys-core`
  - Variants: `qsys`, `qsys_core`, `qsys-core`
- Canonical target: `qsys-touchpanel`
  - Variants: `qsys_touchpanel`, `qsys-touchpanel`
- Canonical target: `qsys-nv-endpoint`
  - Variants: `qsys_nv_endpoint`, `qsys-nv-decoder`, `qsys_nv_decoder`, `qsys-nv-endpoint`
  - Observed subtype tokens also present in suggestion logic: `qsys-nv21`, `qsys-nv32`

### 3.3 Biamp family

- Canonical target: `biamp-tesira`
  - Variants: `biamp`, `tesira`, `biamp_tesira`, `biamp-tesira`

### 3.4 Video processing

- Canonical target: `video-wall-processor`
  - Variants: `video_wall_processor`, `video-wall`, `video-wall-processor`

Contract rule:

- Normalization is for contract-level mapping only in this stage.  
- No endpoint/output schema rewrite is performed in W6.0.5.

---

## 4) Implementation Guardrails for W6.1+

- Do not assume runtime-only fields are persisted.
- Always handle large-inventory shortcut branch from `validate_systems`.
- Treat `results[]` row variability (especially error rows) as expected; consume defensively.
- Prefer canonical object mapping adapters over direct raw-field coupling in new endpoints/screens.

---

## 5) Ch 6 Planning Outcome

This contract is the canonical source for:

- W6.1 requirements generation mapping
- W6.2 requirements UI wiring
- W6.3 connectivity flow generation
- W6.4 system aggregation and downstream handover/advisory outputs

