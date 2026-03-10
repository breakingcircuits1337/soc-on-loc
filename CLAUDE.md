# CLAUDE.md — SOC-on-LOC Codebase Guide

SOC-on-LOC is an AI-native Security Operations Orchestration platform built for autonomous cybersecurity defense. It is a fork of [paperclipai/paperclip](https://github.com/paperclipai/paperclip) re-scoped for cyber defense, developed by [Breaking Circuits LLC](https://breakingcircuits.com).

---

## Architecture Overview

**Monorepo** managed with **pnpm workspaces**. All packages live under `packages/` or as top-level apps.

```
soc-on-loc/
├── packages/
│   ├── shared/          # Domain constants, types, Zod validators
│   ├── db/              # Drizzle ORM schema, migrations, client
│   ├── adapter-utils/   # Shared adapter primitives
│   └── adapters/        # Pluggable agent adapters
│       ├── claude-local/
│       ├── codex-local/
│       ├── cursor-local/
│       ├── openclaw/
│       └── opencode-local/
├── server/              # Express 5 API server
├── ui/                  # React 19 + Vite 6 frontend dashboard
├── cli/                 # Commander.js CLI (pnpm sentinel)
├── skills/              # Claude skill SKILL.md files
├── doc/                 # Developer guides and specs
├── scripts/             # Build and dev automation
└── .github/workflows/   # GitHub Actions CI
```

**Technology stack:**
- Language: TypeScript (strict mode everywhere)
- Runtime: Node.js 20+
- Package manager: pnpm 9.15+
- Backend: Express.js 5.x
- Database: PostgreSQL + Drizzle ORM (embedded PostgreSQL for local dev)
- Frontend: React 19, Vite 6, Tailwind CSS 4, Radix UI
- Auth: better-auth 1.4.18
- Testing: Vitest 3.x
- Real-time: WebSocket (`ws`)
- Logging: pino

---

## Development Commands

```bash
pnpm install              # Install all dependencies
pnpm dev                  # Start server + UI (hot reload)
pnpm dev:server           # Server only
pnpm dev:ui               # UI only (Vite dev server)
pnpm dev:watch            # Watch mode (skips migration prompts)
pnpm build                # Build all packages
pnpm typecheck            # TypeScript check across all packages
pnpm test:run             # Run all tests with Vitest
pnpm db:generate          # Generate new Drizzle migration after schema change
pnpm db:migrate           # Apply pending migrations
pnpm db:backup            # Manual database backup
pnpm sentinel onboard     # Interactive quickstart via CLI
```

CI runs `typecheck`, `test:run`, and `build` on every PR and push to `master`.

---

## Domain Vocabulary

This codebase maps security concepts to platform primitives. Always use the platform term in code and APIs:

| Platform Term   | Security Meaning                        |
|-----------------|-----------------------------------------|
| `company`       | SOC / Defender Team                     |
| `agent`         | Defender (AI or human)                  |
| `issue`         | Incident / Finding                      |
| `project`       | Operation / Campaign                    |
| `goal`          | Mission Objective                       |
| `heartbeat`     | Watch Cycle (periodic agent check-in)   |
| `approval`      | Authorization Gate                      |
| `ioc`           | Indicator of Compromise                 |
| `asset`         | Network asset / host in inventory       |
| `threat_feed`   | Threat intelligence source              |

---

## Key Constants — Always Import from `@paperclipai/shared`

Never hardcode domain strings. All enumerations live in `packages/shared/src/constants.ts`.

```typescript
import {
  AGENT_ROLES,        // "ciso" | "incident_commander" | "soc_analyst" | ...
  ISSUE_PRIORITIES,   // "critical" | "high" | "medium" | "low" | "info"
  ISSUE_STATUSES,     // "new" | "triaging" | "confirmed" | "investigating" | ...
  FINDING_TYPES,
  KILL_CHAIN_STAGES,  // Lockheed Martin kill chain
  MITRE_TACTICS,      // "TA0001" through "TA0043"
  MITRE_TECHNIQUES,
  IOC_TYPES,          // "ip" | "domain" | "hash_sha256" | ...
  ASSET_TYPES,
  ASSET_CRITICALITY,  // "crown_jewel" | "critical" | ...
  THREAT_FEED_TYPES,  // "nvd" | "misp" | "otx" | "stix_taxii" | ...
  CONTAINMENT_ACTION_TYPES,
  COMPLIANCE_FRAMEWORKS, // "nist_csf" | "iso_27001" | "pci_dss" | ...
} from "@paperclipai/shared";
```

---

## Database

### Schema location
All Drizzle schema files: `packages/db/src/schema/`

Key tables:
- `companies` — SOC teams
- `agents` — Defenders
- `issues` — Incidents/findings (extended with CVSS, MITRE ATT&CK, kill chain, SLA fields)
- `iocs` — Indicators of Compromise
- `assets` / `network_assets` — Asset inventory
- `threat_feeds` — Threat intelligence sources
- `approvals` — Authorization gates
- `heartbeat_runs` / `heartbeat_run_events` — Watch cycles
- `cost_events` — Token/API cost tracking
- `activity_log` — Immutable audit trail

### Migrations workflow
After changing any schema file, always regenerate and apply:
```bash
pnpm db:generate   # Generates SQL migration file under packages/db/src/migrations/
pnpm db:migrate    # Applies pending migrations
```

Never write raw SQL mutations against the database directly.

### Local dev database
By default, an **embedded PostgreSQL** instance runs at `~/.paperclip/instances/default/db/`. No external database needed for development.

To reset: `rm -rf ~/.paperclip/instances/default/db && pnpm dev`

To use an external PostgreSQL, set `DATABASE_URL` in `.env`.

---

## Server (Express API)

**Entry point:** `server/src/index.ts` → `server/src/app.ts`

Routes live in `server/src/routes/` and are mounted under `/api`. Each route file exports a Router:

```typescript
import { Router } from "express";
const router = Router();
router.get("/", async (req, res) => { ... });
export default router;
```

**Auth middleware:** `server/src/middleware/auth.ts` — board-level authorization for mutations.

**Real-time:** `server/src/realtime/live-events-ws.ts` — WebSocket for live heartbeat events and streaming.

**Adapters:** `server/src/adapters/` and `packages/adapters/` — pluggable agent integrations. Available adapter types:
- `claude_local`, `codex_local`, `opencode_local`, `cursor` — local AI agents
- `openclaw` — continuous agent via SSE + webhook
- `http` — generic REST endpoint
- `process` — raw subprocess/shell
- `siem` — SIEM webhook receiver (Splunk, Elastic, Sentinel)
- `threat_feed` — CVE/NVD/MISP/OTX/STIX feed poller
- `scanner` — nmap/nuclei/OpenVAS wrapper
- `edr` — EDR alert webhook (CrowdStrike, SentinelOne)

---

## Frontend (React UI)

**Entry point:** `ui/src/main.tsx` → `ui/src/App.tsx`

**Path alias:** Use `@/*` to import from `ui/src/`:
```typescript
import { Button } from "@/components/ui/button";
```

**Data fetching:** TanStack Query (`@tanstack/react-query`). All server state goes through React Query hooks.

**Styling:** Tailwind CSS 4 utility classes. No CSS modules; no inline styles.

**Component primitives:** Radix UI headless components (`@radix-ui/*`).

**Icons:** `lucide-react`.

**Routing:** React Router v7 (`react-router-dom`).

---

## CLI

**Binary:** `pnpm sentinel` (or `paperclipai`)

**Entry point:** `cli/src/index.ts`

Commands live in `cli/src/commands/`. The CLI uses Commander.js for argument parsing and `@clack/prompts` for interactive flows.

---

## Packages: `@paperclipai/shared`

The shared package exports:
- **Constants** (`constants.ts`): All domain enumerations
- **Types** (`types/`): Core TypeScript types
- **Validators** (`validators/`): Zod schemas for request/response validation
- **Config schema** (`config-schema.ts`): Instance configuration shape
- **API constants** (`api.ts`): Route and field name constants

Always import from `@paperclipai/shared` rather than re-defining types or strings.

---

## Secrets Management

Never commit secrets. The platform has a built-in secrets provider abstraction:

| Provider | Use case |
|---|---|
| `local_encrypted` | Default for dev; key at `~/.paperclip/instances/default/secrets/master.key` |
| `aws_secrets_manager` | AWS deployments |
| `gcp_secret_manager` | GCP deployments |
| `vault` | HashiCorp Vault enterprise |

Set via config or `PAPERCLIP_SECRETS_PROVIDER` env var.

---

## Environment Variables

Minimal required for local dev (`.env`):
```
DATABASE_URL=postgres://paperclip:paperclip@localhost:5432/paperclip  # optional; embedded if unset
PORT=3100
SERVE_UI=false
```

Other notable vars:
```
PAPERCLIP_HOME                    # Config home (default: ~/.paperclip)
PAPERCLIP_INSTANCE_ID             # Instance name (default: default)
PAPERCLIP_SECRETS_STRICT_MODE     # true/false
PAPERCLIP_MIGRATION_AUTO_APPLY    # Skip migration prompt
HOST                              # Bind host
ANTHROPIC_API_KEY
OPENAI_API_KEY
```

---

## TypeScript Conventions

- **Strict mode** is enforced everywhere (`"strict": true` in all tsconfigs).
- **Module system:** `NodeNext` for server/CLI packages; `ESNext` (bundler) for UI.
- **Naming:**
  - `PascalCase` — types, interfaces, classes, React components
  - `camelCase` — variables, functions, object properties
  - `UPPER_SNAKE_CASE` — exported constants (e.g., `AGENT_ROLES`, `IOC_TYPES`)
  - `kebab-case` — filenames and directories
- Use `fileURLToPath(import.meta.url)` when building paths from ESM module location.
- Never use `any` unless interfacing with truly untyped third-party code; prefer `unknown`.

---

## Database Column Conventions

- `snake_case` column names in Drizzle schema
- All tables include `createdAt` and `updatedAt` with timezone
- Foreign keys named `<table>_id` (e.g., `company_id`, `agent_id`)
- Soft deletes where applicable (check existing table patterns before adding hard deletes)

---

## Testing

Tests are colocated or in `__tests__/` directories. Run with:
```bash
pnpm test:run        # All tests
pnpm typecheck       # Type checking
```

Test coverage spans: `packages/db`, `packages/adapters/opencode-local`, `server`, `ui`, `cli`.

Write tests for new routes, services, and adapter logic. The CI pipeline will fail if tests or typechecks fail.

---

## CI/CD

GitHub Actions workflow: `.github/workflows/ci.yml`

Pipeline steps:
1. `pnpm install --frozen-lockfile`
2. `pnpm -r typecheck`
3. `pnpm test:run`
4. `pnpm build`

Triggered on PRs to `master` and pushes to `master`. Concurrent runs are cancelled.

---

## Skills

Reusable Claude skill definitions are in `skills/`. Each skill has a `SKILL.md` with purpose, API references, and example invocations. Existing skills:
- `paperclip/` — Heartbeat/watch cycle instructions
- `paperclip-create-agent/` — Creating new defenders
- `para-memory-files/` — Memory file management
- `release/` — Release automation
- `release-changelog/` — Changelog generation
- `create-agent-adapter/` — New adapter scaffolding

---

## Documentation

Extended guides in `doc/`:
- `DEVELOPING.md` — Local dev setup, database modes
- `DATABASE.md` — PostgreSQL options (embedded, Docker, Supabase)
- `CLI.md` — Full CLI reference
- `DEPLOYING.md` — Deployment modes (`local_trusted` vs `authenticated`)
- `DOCKER.md` — Docker/docker-compose setup
- `SPEC.md` / `SPEC-implementation.md` — Product specification
- `TASKS.md` — Development task tracking
- `PUBLISHING.md` — npm publishing workflow

---

## Common Mistakes to Avoid

1. **Hardcoding domain strings** — always use constants from `@paperclipai/shared`.
2. **Direct SQL** — use Drizzle ORM queries; never raw SQL mutations.
3. **Skipping migrations** — after any schema change, run `pnpm db:generate` then `pnpm db:migrate`.
4. **Committing secrets** — use the secrets provider; never put keys in source.
5. **Ignoring strict TypeScript** — fix type errors; don't cast to `any` to silence them.
6. **Adding UI state outside React Query** — server state belongs in React Query, not component state.
7. **Using non-standard adapter patterns** — follow existing adapter interface in `packages/adapter-utils/`.
