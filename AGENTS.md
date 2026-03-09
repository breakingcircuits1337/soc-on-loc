# AGENTS.md

Guidance for human and AI contributors working in the SOC-on-LOC repository.

## 1. Purpose

SOC-on-LOC is a control plane for AI-powered Security Operations Centers.
It is a fork of [paperclipai/paperclip](https://github.com/paperclipai/paperclip) redomained for cyber defense.
Built by [Breaking Circuits LLC](https://breakingcircuits.com).

The current implementation target is V1. Core paperclip orchestration engine is preserved;
cyber defense domain constants, schema, and adapters are layered on top.

## 2. Read This First

Before making changes, read in this order:

1. `doc/GOAL.md` — Original paperclip vision (orchestration primitives still apply)
2. `doc/SPEC-implementation.md` — Implementation spec (V1 target)
3. `doc/DEVELOPING.md` — Development workflow
4. `doc/DATABASE.md` — Schema patterns and migration guide
5. `packages/shared/src/constants.ts` — **SOC-on-LOC domain constants** (cyber-specific)

`doc/SPEC.md` is long-horizon product context from paperclip; treat as architecture reference.

## 3. Domain Vocabulary

This codebase uses the paperclip data model but with cyber defense semantics.
When reading code, apply these mappings:

| Code/DB term      | SOC-on-LOC meaning         |
| ----------------- | -------------------------- |
| `company`         | SOC / Defender team        |
| `agent`           | Defender (AI or human)     |
| `issue`           | Incident / Finding         |
| `project`         | Operation / Campaign       |
| `goal`            | Mission objective          |
| `heartbeat`       | Watch cycle                |
| `approval`        | Authorization gate         |

## 4. Key Defender Roles

When creating or configuring agents, use these role values from `AGENT_ROLES` constant:

- `ciso` — Strategic, risk posture, board reporting
- `incident_commander` — Active IR coordination
- `red_teamer` — Adversarial simulation, pen testing
- `vulnerability_analyst` — CVE triage, CVSS scoring
- `blue_teamer` — Detection engineering, SIEM tuning
- `threat_hunter` — Proactive hunting
- `soc_analyst` — Alert triage (Tier 1/2/3)
- `network_defender` — NSM, firewall, IDS/IPS
- `endpoint_defender` — EDR, host-based detection
- `intel_analyst` — TI, IOCs, OSINT
- `malware_analyst` — RE, sandbox, YARA
- `forensics_analyst` — DFIR, evidence
- `compliance_officer` — Framework mapping (NIST/ISO/CIS)

## 5. Incident Severity

Use `ISSUE_PRIORITIES` values — CVSS-aligned:

- `critical` — P0, CVSS 9.0–10.0, active breach
- `high`     — P1, CVSS 7.0–8.9, confirmed threat
- `medium`   — P2, CVSS 4.0–6.9, suspicious activity
- `low`      — P3, CVSS 0.1–3.9, weak signal
- `info`     — Telemetry / audit only

## 6. Adapter Types

SOC-on-LOC extends paperclip's adapter system with security tooling adapters.
Available adapter types (`AGENT_ADAPTER_TYPES`):

- `siem` — SIEM webhook receiver
- `threat_feed` — CVE/NVD/MISP/OTX/STIX feed poller
- `scanner` — nmap / nuclei / OpenVAS process wrapper
- `edr` — EDR alert webhook (CrowdStrike, SentinelOne, etc.)

Plus all original adapters: `http`, `process`, `claude_local`, `codex_local`, `opencode_local`, `cursor`, `openclaw`.

## 7. Schema Extensions

Cyber-specific DB tables live in `packages/db/src/schema/`:

- `assets.ts` — Network asset / host inventory
- `iocs.ts` — Indicators of Compromise
- `threat_feeds.ts` — External intel source registry

The `issues` table is extended with fields:
`cvss_score`, `cve_id`, `mitre_tactic`, `mitre_technique`, `kill_chain_stage`,
`affected_asset_ids`, `ioc_ids`, `source_alert_id`, `mttd_seconds`, `mttr_seconds`,
`sla_deadline_at`, `evidence`, `containment_actions`

## 8. Coding Conventions

- **TypeScript everywhere** — no untyped JS in packages/
- **Drizzle ORM** — all schema changes via migration, never raw SQL mutations
- **Constants from shared** — always import domain constants from `@paperclipai/shared`, never hardcode strings
- **No inline credentials** — use `SECRET_PROVIDERS` pattern for any API keys
- **fileURLToPath** — when constructing file paths from `import.meta.url`, always use `fileURLToPath()` from `node:url` (spaces in path bug)

## 9. Running Tests

```bash
pnpm test:run        # All tests
pnpm typecheck       # Type check all packages
pnpm db:generate     # Generate migrations after schema change
pnpm db:migrate      # Apply pending migrations
```

## 10. Attribution

All contributions to SOC-on-LOC are credited to **Breaking Circuits LLC**.
Upstream paperclip contributions should be upstreamed to paperclipai/paperclip when applicable.
