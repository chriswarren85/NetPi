"""
Conversational Network Query Interface (W13.6)

Serialises current project state into a structured context block and sends
operator questions + context to a configurable LLM backend (Ollama local or
Anthropic API). Answers are grounded only in project data.

Backends (configured via settings.json under "ai_query_backend"):
  - "ollama"     : local Ollama endpoint (default model: mistral)
  - "anthropic"  : Anthropic API (requires ANTHROPIC_API_KEY env var)
  - "disabled"   : disables the query interface

Pure context-serialisation functions have no I/O dependencies.
"""

import json
import os
import re
from datetime import datetime, timezone


MAX_CONTEXT_DEVICES = 80
MAX_CONTEXT_GROUPS = 40
MAX_CONTEXT_RESULTS = 60


# ── Context Serialiser ────────────────────────────────────────────────────────

def build_query_context(
    devices=None,
    validation_results=None,
    multicast_groups=None,
    topology=None,
    recommendations=None,
    firewall_plan=None,
    system_requirements=None,
    settings=None,
):
    """
    Serialise project state into a compact text block suitable for LLM context.
    Returns (context_text: str, sources_used: list[str]).
    """
    sections = []
    sources_used = []

    settings = settings or {}
    project_name = settings.get("project_name") or "unnamed project"

    sections.append(f"PROJECT: {project_name}\n")

    # Devices
    if devices:
        sources_used.append("devices.json")
        dev_list = list(devices)[:MAX_CONTEXT_DEVICES]
        lines = []
        for d in dev_list:
            ip = d.get("ip") or ""
            name = d.get("name") or d.get("hostname") or ""
            dtype = d.get("type") or d.get("effective_type") or "unknown"
            vlan = d.get("vlan") or ""
            room = d.get("room") or d.get("zone") or ""
            ports = ",".join(str(p) for p in (d.get("open_ports") or [])[:6])
            line = f"  {ip:<18} {name:<20} type={dtype:<22} vlan={vlan:<6} room={room:<12} ports=[{ports}]"
            lines.append(line)
        sections.append("DEVICES (" + str(len(dev_list)) + "):\n" + "\n".join(lines) + "\n")

    # Validation results
    if validation_results:
        sources_used.append("validation_results")
        rows = list(validation_results)[:MAX_CONTEXT_RESULTS]
        fail_rows = [r for r in rows if str(r.get("status") or r.get("overall") or "").lower() in {"fail", "error"}]
        warn_rows = [r for r in rows if str(r.get("status") or r.get("overall") or "").lower() in {"warn", "warning"}]
        sections.append(
            f"VALIDATION SUMMARY: {len(rows)} total, "
            f"{len(fail_rows)} fail, {len(warn_rows)} warn\n"
        )
        if fail_rows:
            lines = []
            for r in fail_rows[:15]:
                ip = r.get("ip") or r.get("device") or ""
                check = r.get("check") or r.get("expected_requirement") or ""
                msg = r.get("message") or r.get("recommended_action") or ""
                lines.append(f"  FAIL {ip:<18} {check:<30} {msg[:60]}")
            sections.append("VALIDATION FAILURES:\n" + "\n".join(lines) + "\n")

    # Multicast groups
    if multicast_groups:
        sources_used.append("multicast_groups.json")
        groups = list(multicast_groups)[:MAX_CONTEXT_GROUPS]
        lines = [
            f"  {g.get('group',''):<18} members={len(g.get('members') or [])} vlan={g.get('vlan','')}"
            for g in groups
        ]
        sections.append("MULTICAST GROUPS (" + str(len(groups)) + "):\n" + "\n".join(lines) + "\n")

    # Recommendations summary
    if recommendations:
        sources_used.append("recommendations")
        recs = list(recommendations)[:20]
        lines = [
            f"  [{r.get('severity','info').upper():<6}] [{r.get('category','?'):<22}] {r.get('title','')[:60]}"
            for r in recs
        ]
        sections.append("RECOMMENDATIONS (" + str(len(recs)) + "):\n" + "\n".join(lines) + "\n")

    # Firewall rules summary
    if firewall_plan:
        sources_used.append("firewall_plan")
        rules = list((firewall_plan.get("rules") or []))[:20]
        if rules:
            lines = [
                f"  {r.get('action','?'):<8} {r.get('protocol',''):<5} src={r.get('source_vlan',''):<10} "
                f"dst={r.get('destination_vlan',''):<10} port={r.get('destination_port','')}"
                for r in rules
            ]
            sections.append("FIREWALL RULES (sample):\n" + "\n".join(lines) + "\n")

    context_text = "\n".join(sections)
    return context_text, sources_used


def build_system_prompt():
    return (
        "You are NetPi, an AI assistant specialising in professional AV over IP commissioning. "
        "You answer questions about the current network project based only on the project data provided below. "
        "Do not invent device names, IP addresses, or configurations not present in the data. "
        "When referencing devices, use their IP address and name from the data. "
        "Be concise, specific, and cite device names where relevant. "
        "If the data does not contain enough information to answer, say so clearly."
    )


# ── LLM Backends ─────────────────────────────────────────────────────────────

def query_ollama(question, context_text, model=None, endpoint=None):
    """Send question + context to a local Ollama instance."""
    import urllib.request

    model = model or "mistral"
    endpoint = endpoint or "http://localhost:11434/api/generate"

    system = build_system_prompt()
    prompt = f"{system}\n\n---PROJECT DATA---\n{context_text}\n---END DATA---\n\nQuestion: {question}"

    payload = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": False,
    }).encode("utf-8")

    req = urllib.request.Request(
        endpoint,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return str(data.get("response") or "").strip()


def query_anthropic(question, context_text, api_key=None, model=None):
    """Send question + context to the Anthropic API."""
    import urllib.request

    api_key = api_key or os.environ.get("ANTHROPIC_API_KEY") or ""
    if not api_key:
        raise ValueError("ANTHROPIC_API_KEY not set")

    model = model or "claude-haiku-4-5-20251001"
    system = build_system_prompt()
    user_message = f"---PROJECT DATA---\n{context_text}\n---END DATA---\n\nQuestion: {question}"

    payload = json.dumps({
        "model": model,
        "max_tokens": 1024,
        "system": system,
        "messages": [{"role": "user", "content": user_message}],
    }).encode("utf-8")

    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = json.loads(resp.read().decode("utf-8"))

    content = data.get("content") or []
    for block in content:
        if block.get("type") == "text":
            return str(block.get("text") or "").strip()
    return ""


def answer_query(question, context, ai_settings=None):
    """
    Route a question + context to the configured backend and return the answer.

    ai_settings: dict with keys: backend, ollama_model, ollama_endpoint,
                 anthropic_model, anthropic_api_key
    """
    ai_settings = ai_settings or {}
    backend = str(ai_settings.get("backend") or "disabled").strip().lower()

    if backend == "disabled" or not backend:
        return {
            "ok": False,
            "answer": None,
            "error": "AI query backend is not configured. Set ai_query_backend in project settings.",
            "backend": "disabled",
        }

    context_text, sources_used = build_query_context(**context)

    try:
        if backend == "ollama":
            answer = query_ollama(
                question,
                context_text,
                model=ai_settings.get("ollama_model"),
                endpoint=ai_settings.get("ollama_endpoint"),
            )
        elif backend == "anthropic":
            answer = query_anthropic(
                question,
                context_text,
                api_key=ai_settings.get("anthropic_api_key") or os.environ.get("ANTHROPIC_API_KEY"),
                model=ai_settings.get("anthropic_model"),
            )
        else:
            return {
                "ok": False,
                "answer": None,
                "error": f"Unknown backend: {backend}",
                "backend": backend,
            }

        return {
            "ok": True,
            "answer": answer,
            "backend": backend,
            "sources_used": sources_used,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    except Exception as e:
        return {
            "ok": False,
            "answer": None,
            "error": str(e),
            "backend": backend,
        }
