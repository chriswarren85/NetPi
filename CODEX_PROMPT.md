# Codex Prompt Page — NetPi Workflow
# Codex Prompt Page — NetPi Workflow

Use this page as the standard prompt source for all Codex work on NetPi.

## Purpose

This project uses:
- **Laptop** as the primary editing and Git machine
- **GitHub** as the source of truth
- **Raspberry Pi** as the deploy target and runtime test box

Codex must work within that model.

---

## Standard Codex Prompt

You are continuing development of NetPi, a Flask + nginx AV network validation tool running on a Raspberry Pi.

Critical rules:
- Treat PROJECT_STATE.md as the single source of truth
- GitHub is the source of truth for code history
- Raspberry Pi is deploy target only
- Do not rewrite working features
- Only apply small surgical patches
- Always inspect files before modifying
- Prefer exact diffs / patch-style changes over broad rewrites
- Always test backend endpoints before touching UI behavior
- Never break existing render logic unless explicitly required
- If behavior, architecture, or workflow changes, update PROJECT_STATE.md
- Always finish with obvious next steps
- Be explicit about whether code is edited, tested, committed, pushed, and deployed

Workflow constraints:
- The laptop is the primary development environment
- The Raspberry Pi is the deployment target
- Do not assume the Pi is where edits are made
- Do not assume code is deployed just because files were changed
- Do not assume code is committed just because a diff exists

Testing instructions must be separated into:
1. Pre-commit checks on the laptop/repo working tree
2. Post-deploy checks on the Raspberry Pi runtime

For each command, explicitly state:
- where to run it
- what success looks like
- what failure likely means

Required final output format:

Task summary:
- <what changed>

Current status:
- Edited: yes/no
- Tested: yes/no
- Committed: yes/no
- Pushed: yes/no
- Deployed: yes/no

Files inspected:
- <file>
- <file>

Files changed:
- <file> — <reason>

What I think was happening:
- <plain English root cause>

What I changed:
- <plain English summary>
- <important implementation detail>
- <risks / assumptions / follow-up checks>

Review:
git status
git diff --stat
git diff

Pre-commit checks on laptop:
# exact commands to run in the repo working tree

Commit on laptop:
# exact git add / git commit commands

Push from laptop:
# exact git push command

Post-deploy checks on Pi:
# exact git pull / restart / curl commands

What to verify after deploy:
- <expected result>
- <expected result>

Next obvious action:
- <single best next step>

---

## Short Prompt Version

Use this for small tasks.

Continue development of NetPi.

Rules:
- Treat PROJECT_STATE.md as the single source of truth
- Do not rewrite working features
- Make only small surgical patches
- Inspect files before modifying
- Always provide:
  - files inspected
  - files changed
  - review commands
  - pre-commit laptop checks
  - commit/push commands
  - post-deploy Pi commands
  - next obvious action
- Be explicit about whether code is edited, tested, committed, pushed, and deployed

Task:
<insert task here>

---

## Debug Prompt Version

Use this when troubleshooting a bug or runtime issue.

Continue development of NetPi.

Rules:
- Treat PROJECT_STATE.md as the single source of truth
- Do not rewrite working features
- Backend verification before UI
- Give exact commands, expected output, and likely failure meaning
- Separate laptop checks from Pi runtime checks
- Be explicit about whether the issue is code, git, service, nginx, or network related

Problem:
<describe the failure, logs, curl output, or behavior>

When done, provide:
- likely cause
- files inspected
- exact commands to verify
- exact fix
- exact pre-commit checks
- exact post-deploy Pi checks
- next obvious action

---

## Deployment Model

### Laptop workflow

Run on laptop after Codex changes are accepted:

cd C:\pi-projects\netpi
git status
git diff --stat
git diff
git add -A
git commit -m "Describe the change"
git push origin main

### Pi workflow

Run on Pi after pushing from laptop:

cd ~/netpi
git pull origin main
sudo systemctl restart netpi
sudo systemctl restart nginx
curl -I http://127.0.0.1/tools/
curl -I http://127.0.0.1/tools/devices

### Backend/API check example

curl -s -X POST http://127.0.0.1/tools/api/validate_systems \
  -H "Content-Type: application/json" \
  -d '{}' | jq

---

## Operator Rules

Always remember:
- **Laptop = edit, commit, push**
- **GitHub = source of truth**
- **Pi = pull, restart, verify**

Avoid:
- editing on laptop and Pi in parallel
- trusting “made changes” without review/test
- assuming deployment happened automatically

---

## Good Task Examples

### Example 1 — backend refinement

[PASTE STANDARD CODEX PROMPT]

Task:
Strengthen AV role inference so detected systems prefer true role-based matches over weak peer inference. Inspect backend logic first, make the smallest safe patch, and give me exact review, laptop test, commit, push, and Pi deploy commands.

### Example 2 — UI cleanup

[PASTE SHORT PROMPT]

Task:
Clean up the Devices page button spacing without changing renderTable() behavior or existing endpoint calls.

### Example 3 — debugging

[PASTE DEBUG PROMPT]

Problem:
After pulling the latest code on the Pi, /tools/ intermittently returns 502 even though systemd shows the service as active.

---

## Prompt Design Rule

The most important line to keep in every Codex prompt is:

Be explicit about whether the code is edited, tested, committed, pushed, and deployed.

That line prevents Codex from sounding finished when it has only changed files.