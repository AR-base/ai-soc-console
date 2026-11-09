# AI-Powered SOC Console

A single-page SOC console built for the ESAIP MSc class exercise **"Build your AI-powered SOC"**: a shared Wazuh SIEM watching a Windows 11 lab endpoint, four teams, and one final challenge — **log → alert → AI-assisted analysis → SOC decision**.

**Live site:** https://ar-base.github.io/ai-soc-console/

## What it does

| Tab | Team | Purpose |
|---|---|---|
| **Detection** | Team 2 | Safe Windows test scenarios, Wazuh queries, alert JSON intake, auto-generated "why it fired" text, handoff table |
| **AI analysis** | Team 3 | Redacts personal data into stable tokens, builds a strict prompt, and checks every AI fact against the exact alert field it cites |
| **Command center** | Team 4 | Five live KPIs, attack timeline, decisions per incident, response playbook, two-minute executive briefing |
| **Method & limits** | All | Prompts, verification method, limitations, evidence pack |

## Key ideas

- **Redaction before AI.** Accounts, hosts, IPs, emails and account SIDs become tokens (`USER_1`, `HOST_3`, `SID_1`…). A value keeps its token for good, so the AI can link alerts without ever learning who is involved. A leak check confirms nothing slipped through.
- **Evidence-bound AI.** Every AI *fact* must name the alert field it came from (e.g. `data.win.eventdata.logonType = 7`); the console reads that field and marks ✓ match, ✕ conflict / missing, or ? opinion. A person makes the final call.
- **Real data.** The three incidents are real alerts from the lab VM (8 Nov 2026): a wrong Windows Hello PIN (rule 60122), the unlock four seconds later with an admin token (67022), and a SYSTEM display-name update (60110). Personal details are replaced with placeholders.
- **Honest KPIs.** The detection-time KPI spots that every alert arrived 208–209 s after its event — a constant gap that points to the VM clock, not slow detection.

## Run, build, test

Open `index.html` in a browser — no server or install needed. Work is saved in your browser only.

```bash
python3 build.py          # rebuilds index.html from src/
node --test tests/core.test.js   # 24 tests: redaction, leak checks, claim checks, KPIs, hostile input
```

`src/core.js` holds all logic as pure functions (tested in Node); `src/app.html` is the UI; `src/data.js` holds the lab alerts, analyses, test commands and playbook.

## Security notes

- Strict Content-Security-Policy: no external scripts, no network calls; only Google Fonts.
- All data is rendered as text (no `innerHTML` for data); pasted alerts and AI answers are size-limited and validated.
- Lab data only. The prompts and redaction rules were not tested on production traffic.

---
Built by **Pinninti Sai Anish** · ESAIP MSc Cybersecurity & Data Science.
