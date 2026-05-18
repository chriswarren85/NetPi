# AI Intelligence Layer

The `/ai` package provides adaptive intelligence on top of NetPi's deterministic validation core.

## Architectural Boundary

**AI augments, infers, and recommends — it never replaces core validation logic.**

### Read-only data sources (inputs)

| File | Contents |
|------|----------|
| `devices.json` | Discovered device inventory with attributes |
| `topology.json` | Network topology map |
| `multicast_groups.json` | IGMP/multicast group membership |
| `data/fingerprints.json` | Per-device evidence store (HTTP, SSH, mDNS, ports) |
| `data/device_evidence.json` | Raw scan evidence keyed by IP/hostname |
| Validation results (in-memory) | Output of `run_validation`, `run_system_validation` |
| Requirements results (in-memory) | Output of `generate_device_requirements` |
| Firewall plan (in-memory) | Output of `_compose_firewall_plan` |

AI modules receive copies of this data — they never hold live references or write back to these files.

### Output contract

Every AI function returns structured JSON with this general shape:

```json
{
  "ok": true,
  "source": "<module-name>",
  "generated_at": "<ISO-8601>",
  "<result-key>": { ... }
}
```

AI outputs are **suggestions only**. They are returned to the API caller as structured JSON. The caller (operator or UI) decides whether to act on them. Confirmed actions may be persisted by the core layer — never by an AI module directly.

### Module overview

| Sub-package | Purpose |
|-------------|---------|
| `fingerprinting/` | W13.1 — Device type classifier using observed attributes + learned pattern library |
| `recommendations/` | W13.3 — Evidence-backed, context-aware recommendation engine |
| `anomaly_detection/` | W13.4 — Baseline recorder + statistical anomaly comparison |
| `models/` | W13.5 — Topology pattern library + deployment pattern scorer |
| `query/` | W13.6 — Natural language query interface (context serialiser + LLM bridge) |

### Failure safety

AI module failures must never crash core validation. All AI endpoints wrap calls in try/except and return `{"ok": false, "error": "..."}` on failure. The UI gates AI panels behind availability checks.
