# SOC-on-LOC

**AI-Native Security Operations Orchestration — Local, Autonomous, Defender-Led**

> Built by [Breaking Circuits LLC](https://breakingcircuits.com) &nbsp;|&nbsp; Forked from [paperclipai/paperclip](https://github.com/paperclipai/paperclip)

---

## What is SOC-on-LOC?

SOC-on-LOC is an open-source AI agent orchestration platform purpose-built for **cybersecurity operations**. Where Paperclip runs AI companies, SOC-on-LOC runs AI Security Operations Centers — fully local, fully autonomous, fully under your control.

Spin up a team of AI defenders. Assign roles. Set mission objectives. Watch your SOC operate 24/7 with no human babysitting required.

**If OpenClaw is an _analyst_, SOC-on-LOC is the _SOC_.**

|        | Step                     | Example                                                                       |
| ------ | ------------------------ | ----------------------------------------------------------------------------- |
| **01** | Define the mission       | _"Detect, contain, and remediate all critical incidents within a 4-hour SLA."_ |
| **02** | Build your defender team | CISO, Incident Commander, SOC Analysts, Threat Hunters, Red Teamers — any AI. |
| **03** | Approve and activate     | Set budgets. Review strategy. Hit go. Monitor from the SOC dashboard.         |

---

## SOC-on-LOC is right for you if

- ✅ You want a **fully autonomous SOC** that operates 24/7 without manual intervention
- ✅ You need to **coordinate many different AI defenders** (OpenClaw, Claude, Codex, custom agents) toward a common security mission
- ✅ You want **full incident lifecycle management** — from raw alert to closed ticket — handled by AI
- ✅ You need **authorization gates** before countermeasures deploy (you're the board, not the bottleneck)
- ✅ You want every decision **permanently logged** with MITRE ATT&CK and Kill Chain context
- ✅ You want to **monitor costs** and enforce token budgets per defender
- ✅ You want to manage your SOC **from your phone**

---

## Features

<table>
<tr>
<td align="center" width="33%">
<h3>🛡️ Bring Your Own Defender</h3>
Any AI, any runtime. OpenClaw, Claude Code, custom scripts, SIEM webhooks. If it can receive a watch cycle, it's hired.
</td>
<td align="center" width="33%">
<h3>🚨 Incident Lifecycle</h3>
Full IR workflow from raw alert to closure. CVSS severity, kill chain tagging, MITRE ATT&CK, evidence and containment tracking.
</td>
<td align="center" width="33%">
<h3>🎯 Mission Alignment</h3>
Every incident traces back to the SOC mission. Defenders always know <em>what</em> to defend and <em>why</em>.
</td>
</tr>
<tr>
<td align="center">
<h3>🔁 Watch Cycles</h3>
Defenders wake on schedule or on assignment, triage alerts, escalate, contain, and report back. Heartbeats with live streaming output.
</td>
<td align="center">
<h3>🔐 Authorization Gates</h3>
You are the board. Approve defender hires, countermeasure deployments, risk acceptances, and CISO strategy — at any time.
</td>
<td align="center">
<h3>💰 Cost Control</h3>
Monthly token budget per defender. When they hit the limit, they stand down. No runaway spend.
</td>
</tr>
<tr>
<td align="center">
<h3>🧠 MITRE ATT&CK</h3>
Incidents mapped to Kill Chain stage and ATT&CK tactic codes. CVSS scoring built into the severity model.
</td>
<td align="center">
<h3>📋 Immutable Audit Log</h3>
Every decision, every tool call, every escalation — permanently recorded. Full compliance trail.
</td>
<td align="center">
<h3>🏢 Multi-SOC Portfolio</h3>
One deployment, many SOCs. Complete data isolation. One control plane for your entire security operation.
</td>
</tr>
</table>

---

## SOC-on-LOC vs. Paperclip

| Paperclip Concept   | SOC-on-LOC Equivalent   | Notes                                                |
| ------------------- | ----------------------- | ---------------------------------------------------- |
| Company             | SOC / Defender Team     | One SOC per deployment or multi-SOC portfolio        |
| Agent               | Defender                | Roles: CISO, Analyst, Threat Hunter, Red Teamer...   |
| Issue / Ticket      | Incident / Finding      | Full incident lifecycle with CVSS severity           |
| Heartbeat           | Watch Cycle             | Defenders wake, triage alerts, act, report           |
| Goal                | Mission Objective       | Traced from SOC mission → team → defender → task     |
| Project             | Operation / Campaign    | Grouped IR or hunt operations                        |
| Approval            | Authorization Gate      | Deploy countermeasures, accept risk, hire defenders  |
| Budget              | Token / Cost Envelope   | Per-defender monthly spend cap                       |

---

## Defender Roles

| Role                   | Responsibility                                                |
| ---------------------- | ------------------------------------------------------------- |
| `ciso`                 | Strategic direction, risk posture, board reporting            |
| `incident_commander`   | Leads active IR — coordinates containment and remediation     |
| `red_teamer`           | Adversarial simulation, penetration testing, purple team      |
| `vulnerability_analyst`| CVE triage, CVSS scoring, patch prioritization                |
| `blue_teamer`          | Active defense, SIEM rule tuning, detection engineering       |
| `threat_hunter`        | Proactive hypothesis-driven hunting for hidden threats        |
| `soc_analyst`          | Tier 1/2/3 alert triage, investigation, escalation            |
| `network_defender`     | NSM, firewall management, IDS/IPS tuning                      |
| `endpoint_defender`    | EDR management, host-based detection and response             |
| `intel_analyst`        | Threat intelligence, IOC tracking, OSINT, dark web            |
| `malware_analyst`      | Reverse engineering, sandbox analysis, YARA rule development  |
| `forensics_analyst`    | Digital forensics, chain of custody, evidence collection      |
| `compliance_officer`   | NIST / ISO 27001 / FISMA / CIS framework mapping              |

---

## Incident Lifecycle

```
new → triaging → confirmed → investigating → containing → remediating → resolved → closed
                                                                       → false_positive
                                                                       → accepted_risk
```

**Severity (CVSS-aligned)**:
- `critical` — P0: active breach, ransomware, data exfil in progress (CVSS 9.0–10.0)
- `high`     — P1: confirmed threat, immediate response required (CVSS 7.0–8.9)
- `medium`   — P2: suspicious activity, investigation needed (CVSS 4.0–6.9)
- `low`      — P3: low-confidence signal (CVSS 0.1–3.9)
- `info`     — Telemetry / audit only

---

## Intelligence Framework

**Kill Chain Stages** (Lockheed Martin):
`reconnaissance` → `weaponization` → `delivery` → `exploitation` → `installation` → `c2` → `exfiltration`

**MITRE ATT&CK Tactics**: TA0001 through TA0043 (14 tactic codes tracked per incident)

**IOC Types**: IP, CIDR, domain, URL, MD5/SHA1/SHA256, email, file path, registry key, user agent, TLS cert, mutex

**Compliance Frameworks**: NIST CSF, NIST 800-53, ISO 27001, FISMA, CIS v8, SOC 2, PCI DSS, HIPAA, CMMC

---

## Adapter Types

| Adapter          | Description                                                  |
| ---------------- | ------------------------------------------------------------ |
| `openclaw`       | OpenClaw continuous agent — SSE + webhook transport          |
| `http`           | Generic HTTP — any REST-callable agent                       |
| `claude_local`   | Claude Code local process                                    |
| `opencode_local` | OpenCode local process                                       |
| `siem`           | SIEM webhook receiver (Splunk, Elastic, Sentinel)            |
| `threat_feed`    | CVE/NVD/MISP/OTX/STIX feed poller                           |
| `scanner`        | nmap / nuclei / OpenVAS process wrapper                      |
| `edr`            | EDR alert webhook (CrowdStrike, SentinelOne, etc.)           |
| `process`        | Raw subprocess / shell adapter                               |

---

## Quickstart

Open source. Self-hosted. No account required.

```bash
git clone https://github.com/breakingcircuits1337/soc-on-loc.git
cd soc-on-loc
pnpm install
pnpm dev
```

API server starts at `http://localhost:3100`. Embedded PostgreSQL is created automatically — no setup required.

> **Requirements:** Node.js 20+, pnpm 9.15+

### First-time setup

```bash
pnpm sentinel onboard --yes    # Non-interactive quickstart
# or
pnpm sentinel onboard          # Interactive setup
```

---

## Development

```bash
pnpm dev              # Full dev (API + UI with hot reload)
pnpm dev:server       # Server only
pnpm build            # Build all packages
pnpm typecheck        # Type check all packages
pnpm test:run         # Run tests
pnpm db:generate      # Generate DB migration after schema change
pnpm db:migrate       # Apply pending migrations
pnpm db:backup        # Manual database backup
```

---

## Architecture

SOC-on-LOC is a Node.js + React monorepo built on the Paperclip orchestration engine, with a full cyber defense domain layer on top.

```
packages/
  shared/        — Domain constants, types, validators (cyber defense semantics)
  db/            — Drizzle ORM + PGlite embedded PostgreSQL
                   Extended schema: assets, iocs, threat_feeds
  adapters/      — Adapter implementations (openclaw, http, siem, scanner, edr...)
  adapter-utils/ — Shared adapter primitives
server/          — Express API server
ui/              — React + Vite SOC dashboard
cli/             — sentinel CLI (onboard, doctor, run, heartbeat)
```

### Schema Extensions

Cyber-specific tables beyond the Paperclip base:
- `assets` — Network asset / host inventory
- `iocs` — Indicators of Compromise
- `threat_feeds` — External intel source registry

The `issues` table is extended with:
`cvss_score`, `cve_id`, `mitre_tactic`, `mitre_technique`, `kill_chain_stage`,
`affected_asset_ids`, `ioc_ids`, `source_alert_id`, `mttd_seconds`, `mttr_seconds`,
`sla_deadline_at`, `evidence`, `containment_actions`

---

## Roadmap

- [ ] SIEM webhook adapter (Elastic / Splunk / Sentinel ingest)
- [ ] Threat feed poller (NVD / MISP / OTX / STIX-TAXII)
- [ ] Network scanner adapter (nmap / nuclei)
- [ ] EDR alert webhook adapter (CrowdStrike, SentinelOne)
- [ ] Automated countermeasure playbooks
- [ ] MITRE ATT&CK Navigator integration
- [ ] SOC metrics dashboard (MTTD, MTTR, SLA tracking)
- [ ] Multi-SOC portfolio view
- [ ] Export incident reports (STIX 2.1, PDF)

---

## Contributing

We welcome contributions. See [AGENTS.md](AGENTS.md) for the development guide, domain vocabulary, and coding conventions.

---

## Credits

SOC-on-LOC is built and maintained by **[Breaking Circuits LLC](https://breakingcircuits.com)**.

Forked from [paperclipai/paperclip](https://github.com/paperclipai/paperclip) — MIT License.

---

## License

MIT &copy; 2026 Breaking Circuits LLC

---

*Built for defenders who want to run a SOC, not babysit a script.*
