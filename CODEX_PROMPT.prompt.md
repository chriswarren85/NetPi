# Codex Prompt Page - NetPi Workflow

Use this page as the single prompt standard for NetPi tasks.

## Operating Model

- Laptop: edit, test, commit, push
- GitHub: source of truth for code history
- Raspberry Pi: deploy target and runtime validation
- `PROJECT_STATE.md`: source of truth for current project state

## Unified Rules (Single Checklist)

Follow these ordered steps for every task.
If any step conflicts with another rule, use **Conflict Resolution Priority** below.

1. **Understand first**
   - Read `PROJECT_STATE.md`
   - Inspect the target files before changing anything

2. **Plan the patch**
   - Identify the smallest change in lines of code that maintains safety and correctness
   - If the task requires modifying existing logic, preserve API contracts and the behavior of all existing functionality unless explicitly stated otherwise
   - If minimal change conflicts with contract preservation, prefer preserving contracts and split the work

3. **Patch safely**
   - Make surgical edits, not broad rewrites
   - Preserve existing render behavior unless the task explicitly requires change

4. **Validate in order**
   - Test backend/API behavior before UI behavior
   - Run laptop pre-commit checks before committing
   - After push, run Raspberry Pi post-deploy checks

5. **Report clearly**
   - Always state status: edited/tested/committed/pushed/deployed (`yes`/`no`)
   - For each command, state:
     - where it runs (Laptop or Pi)
     - success criteria
     - likely failure meaning

## Conflict Resolution Priority

If rules conflict, apply this priority order (highest first):

1. **Do not break contracts or known-good behavior**
   - Preserve API contracts and required runtime behavior first.

2. **Maintain correctness and safety**
   - Prefer changes that keep backend/UI behavior correct and verifiable.

3. **Follow validation order**
   - Backend/API validation takes priority over UI-only validation.

4. **Minimize blast radius**
   - Within the safe/correct option set, choose the smallest surgical patch.

5. **Be explicit about tradeoffs**
   - If a higher-priority rule forces a larger change, state that explicitly in the report.

Tie handling:
- If two priorities appear equal, choose the option that is easier to verify with tests.
- If still tied, choose the option that changes fewer lines and fewer files.

Decision rule:
- If preserving API contracts conflicts with minimal changes, **prioritize preserving API contracts**.
- If minimal changes conflict with testability, **prioritize testability/correctness**.

Examples:
- Example A: A 2-line change alters response JSON shape, while a 12-line change keeps the current API contract.
  - Choose the 12-line change (contract preservation wins).
- Example B: A 4-line UI tweak passes visually but leaves backend ambiguity, while an 8-line backend+UI patch is testable end-to-end.
  - Choose the 8-line patch (correctness/testability wins).
- Example C: Two valid fixes both preserve behavior; one changes 1 file, the other changes 3 files.
  - Choose the 1-file fix (smaller verified blast radius).

When breaking contracts is unavoidable:
- Do not break API contracts or existing behavior unless the task explicitly authorizes it.
- If unavoidable, document exactly what breaks, impacted endpoints/features, and migration/compatibility steps.
- Add a follow-up task to restore compatibility (or provide a compatibility layer) as soon as possible.

## Required Output Template

Use this at the end of every task:

Task summary:
- <what changed>

Status:
- Edited: yes/no
- Tested: yes/no
- Committed: yes/no
- Pushed: yes/no
- Deployed: yes/no

Files inspected:
- <file>

Files changed:
- <file> - <reason>

Root cause (plain English):
- <what was happening>

Fix summary:
- <what was changed>
- <key implementation detail>
- <risk/assumption/follow-up>

Verification commands:
- <command> | Where: <Laptop/Pi> | Success: <...> | Failure likely means: <...>

Review commands:
```bash
git status
git diff --stat
git diff
```

Next obvious action:
- <single best next step>

## Deployment Commands Reference

Laptop:

```bash
cd C:\pi-projects\netpi
git status
git diff --stat
git diff
git add -A
git commit -m "Describe the change"
git push origin main
```

Pi:

```bash
cd ~/netpi
git pull origin main
sudo systemctl restart netpi
sudo systemctl restart nginx
curl -I http://127.0.0.1/tools/
curl -I http://127.0.0.1/tools/devices
```

Backend/API check example:

```bash
curl -s -X POST http://127.0.0.1/tools/api/validate_systems \
  -H "Content-Type: application/json" \
  -d '{}' | jq
```

## Core Prompt Snippet

Use this for most tasks:

Continue development of NetPi (Flask + nginx on Raspberry Pi).
Follow the Unified Rules checklist exactly.
Make minimal safe changes, validate backend before UI, and finish with the Required Output Template.
Be explicit about edited/tested/committed/pushed/deployed status.
