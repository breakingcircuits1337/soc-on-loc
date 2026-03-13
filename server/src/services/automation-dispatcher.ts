// SOC-on-LOC — Automation Dispatcher
// Processes cyber-defense adapter results after each successful heartbeat run and
// automatically creates incidents (issues) and ingests IOCs into the database.
//
// Adapter result pipeline:
//   siem       → create issue per critical/high alert (deduped by sourceAlertId)
//   edr        → create issue per critical/high detection (deduped by sourceAlertId)
//   threat_feed → upsert IOCs; create vulnerability issue per critical/high CVE
//   scanner    → create issue per critical/high nuclei finding, or a summary issue
//
// After creating each issue, the assigned agent is woken up immediately via the
// wakeupAgent callback (injected from heartbeat.ts to avoid a circular import).
//
// Breaking Circuits LLC — breakingcircuits.com

import { and, eq, max, sql } from "drizzle-orm";
import type { Db } from "@paperclipai/db";
import { agents, issues, iocs } from "@paperclipai/db";
import { logger } from "../middleware/logger.js";

const CYBER_ADAPTER_TYPES = new Set(["siem", "edr", "threat_feed", "scanner"]);

// --- SLA constants ----------------------------------------------------------

const CRITICAL_SLA_HOURS = 4;
const HIGH_SLA_HOURS     = 24;
const MEDIUM_SLA_DAYS    = 7;

// --- Per-run caps (mirrors the caps in the adapter resultJson) ---------------

const MAX_ALERTS_PER_RUN   = 20;   // SIEM alerts or EDR detections per run
const MAX_CVE_ISSUES_PER_RUN = 10; // CVE vulnerability issues per threat feed run
const MAX_FINDINGS_PER_RUN = 10;   // Nuclei findings per scanner run

// --- Priority mapping -------------------------------------------------------

const SEVERITY_PRIORITY: Record<string, string> = {
  critical: "critical",
  high:     "high",
  medium:   "medium",
  low:      "low",
  info:     "info",
};

function normalizePriority(severity: string): string {
  return SEVERITY_PRIORITY[severity.toLowerCase()] ?? "medium";
}

function isCriticalOrHigh(severity: string): boolean {
  return /critical|high/i.test(severity);
}

// --- Shared helpers ---------------------------------------------------------

/** Find the best available agent to assign a new incident to based on role preference. */
async function findAssignee(
  db: Db,
  companyId: string,
  preferredRole: string,
): Promise<string | null> {
  const rows = await db
    .select({ id: agents.id, role: agents.role, status: agents.status })
    .from(agents)
    .where(eq(agents.companyId, companyId));

  if (rows.length === 0) return null;

  // Prefer agents with matching role that are currently idle
  const idlePreferred = rows.find(r => r.role === preferredRole && r.status === "idle");
  if (idlePreferred) return idlePreferred.id;

  // Fall back to any agent with matching role
  const anyPreferred = rows.find(r => r.role === preferredRole);
  if (anyPreferred) return anyPreferred.id;

  // Fall back to soc_analyst or incident_commander
  const fallback = rows.find(r => r.role === "soc_analyst")
    ?? rows.find(r => r.role === "incident_commander")
    ?? rows[0];

  return fallback?.id ?? null;
}

/**
 * Atomically assign the next issue number and insert the issue in a single
 * transaction. A per-company advisory lock (pg_advisory_xact_lock) prevents
 * concurrent runs from fetching the same max(issueNumber), which would cause a
 * unique-constraint violation on the `identifier` column.
 */
async function insertIssueAtomic(
  db: Db,
  values: Omit<typeof issues.$inferInsert, "issueNumber" | "identifier">,
): Promise<{ id: string } | null> {
  return db.transaction(async (tx) => {
    // hashtext() converts the UUID string to a 32-bit int — enough for per-company
    // serialization without risking collisions between different companies.
    await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext(${values.companyId}))`);

    const [row] = await tx
      .select({ maxNum: max(issues.issueNumber) })
      .from(issues)
      .where(eq(issues.companyId, values.companyId!));

    const num = ((row?.maxNum as number | null) ?? 0) + 1;

    const [inserted] = await tx
      .insert(issues)
      .values({ ...values, issueNumber: num, identifier: `SOC-${num}` })
      .returning({ id: issues.id });

    return inserted ?? null;
  });
}

/** Return a Date N hours from now. */
function hoursFromNow(hours: number): Date {
  return new Date(Date.now() + hours * 3_600_000);
}

/** Return a Date N days from now. */
function daysFromNow(days: number): Date {
  return new Date(Date.now() + days * 86_400_000);
}

/** SLA deadline for a given priority, using the named SLA constants. */
function slaDeadline(priority: string): Date | null {
  switch (priority) {
    case "critical": return hoursFromNow(CRITICAL_SLA_HOURS);
    case "high":     return hoursFromNow(HIGH_SLA_HOURS);
    case "medium":   return daysFromNow(MEDIUM_SLA_DAYS);
    default:         return null;
  }
}

// --- SIEM -------------------------------------------------------------------

interface SiemAlert {
  id: string;
  title: string;
  severity: string;
  timestamp: string;
}

async function processSiem(ctx: DispatchContext): Promise<void> {
  const { db, companyId, agentId, runId, resultJson, wakeupAgent } = ctx;

  const rawAlerts = Array.isArray(resultJson.alerts) ? resultJson.alerts : [];
  const criticalAlerts = (rawAlerts as SiemAlert[]).filter(a => isCriticalOrHigh(a.severity));
  if (criticalAlerts.length === 0) return;

  const assigneeId = await findAssignee(db, companyId, "soc_analyst");

  for (const alert of criticalAlerts.slice(0, MAX_ALERTS_PER_RUN)) {
    const sourceAlertId = String(alert.id ?? "");
    if (!sourceAlertId) continue;

    // Deduplicate
    const existing = await db
      .select({ id: issues.id })
      .from(issues)
      .where(and(eq(issues.companyId, companyId), eq(issues.sourceAlertId, sourceAlertId)))
      .then(rows => rows[0] ?? null);
    if (existing) continue;

    const priority = normalizePriority(alert.severity);

    const inserted = await insertIssueAtomic(db, {
      companyId,
      title: String(alert.title ?? `SIEM Alert ${sourceAlertId}`),
      description:
        `**Auto-created from SIEM alert**\n\n` +
        `- Source Alert ID: \`${sourceAlertId}\`\n` +
        `- Severity: ${alert.severity}\n` +
        `- Timestamp: ${alert.timestamp ?? new Date().toISOString()}\n\n` +
        `*Run: ${runId}*`,
      status: "backlog",
      priority,
      findingType: "siem_alert",
      sourceAlertId,
      assigneeAgentId: assigneeId,
      createdByAgentId: agentId,
      slaDeadlineAt: slaDeadline(priority),
    });

    logger.info({ companyId, sourceAlertId, priority }, "automation-dispatcher: created incident from SIEM alert");

    if (inserted?.id && assigneeId) {
      await wakeupAgent?.(assigneeId, inserted.id);
    }
  }
}

// --- EDR --------------------------------------------------------------------

interface EdrDetection {
  id: string;
  title: string;
  severity: string;
  hostname?: string;
  tactic?: string;
  technique?: string;
  timestamp: string;
}

async function processEdr(ctx: DispatchContext): Promise<void> {
  const { db, companyId, agentId, runId, resultJson, wakeupAgent } = ctx;

  const rawDetections = Array.isArray(resultJson.detections) ? resultJson.detections : [];
  const critical = (rawDetections as EdrDetection[]).filter(d => isCriticalOrHigh(d.severity));
  if (critical.length === 0) return;

  const platform = String(resultJson.platform ?? "edr");
  const assigneeId = await findAssignee(db, companyId, "endpoint_defender");

  for (const det of critical.slice(0, MAX_ALERTS_PER_RUN)) {
    const sourceAlertId = String(det.id ?? "");
    if (!sourceAlertId) continue;

    const existing = await db
      .select({ id: issues.id })
      .from(issues)
      .where(and(eq(issues.companyId, companyId), eq(issues.sourceAlertId, sourceAlertId)))
      .then(rows => rows[0] ?? null);
    if (existing) continue;

    const priority = normalizePriority(det.severity);
    const hostname = det.hostname ? `\`${det.hostname}\`` : "unknown";
    const tacticLine = det.tactic ? `\n- MITRE Tactic: ${det.tactic}` : "";
    const techLine = det.technique ? `\n- MITRE Technique: ${det.technique}` : "";

    const inserted = await insertIssueAtomic(db, {
      companyId,
      title: String(det.title ?? `EDR Detection ${sourceAlertId}`),
      description:
        `**Auto-created from EDR detection (${platform})**\n\n` +
        `- Source ID: \`${sourceAlertId}\`\n` +
        `- Host: ${hostname}\n` +
        `- Severity: ${det.severity}` +
        tacticLine + techLine + `\n` +
        `- Timestamp: ${det.timestamp ?? new Date().toISOString()}\n\n` +
        `*Run: ${runId}*`,
      status: "backlog",
      priority,
      findingType: "edr_detection",
      sourceAlertId,
      mitreTactic: det.tactic ?? null,
      mitreTechnique: det.technique ?? null,
      assigneeAgentId: assigneeId,
      createdByAgentId: agentId,
      slaDeadlineAt: slaDeadline(priority),
    });

    logger.info({ companyId, sourceAlertId, platform, priority }, "automation-dispatcher: created incident from EDR detection");

    if (inserted?.id && assigneeId) {
      await wakeupAgent?.(assigneeId, inserted.id);
    }
  }
}

// --- Threat Feed ------------------------------------------------------------

interface IntelItem {
  id: string;
  type: string;
  value: string;
  severity?: string;
  source: string;
  publishedAt?: string;
}

async function processThreatFeed(ctx: DispatchContext): Promise<void> {
  const { db, companyId, agentId, runId, resultJson, wakeupAgent } = ctx;

  const rawItems = Array.isArray(resultJson.items) ? resultJson.items : [];
  const feedType = String(resultJson.feedType ?? "custom");
  const now = new Date();

  // --- 1. Upsert IOCs (non-CVE items) --------------------------------------
  const iocItems = (rawItems as IntelItem[]).filter(i => i.type !== "cve" && i.value);

  for (const item of iocItems) {
    try {
      await db
        .insert(iocs)
        .values({
          companyId,
          iocType: item.type,
          value: item.value,
          confidence: "medium",
          sourceType: feedType,
          sourceName: feedType,
          sourceReference: item.id ?? "",
          isActive: true,
          firstSeenAt: now,
          lastSeenAt: now,
        })
        .onConflictDoUpdate({
          target: [iocs.companyId, iocs.iocType, iocs.value],
          set: { lastSeenAt: now, isActive: true, updatedAt: now },
        });
    } catch (err) {
      logger.warn({ err, iocType: item.type, feedType }, "automation-dispatcher: failed to upsert IOC");
    }
  }

  if (iocItems.length > 0) {
    logger.info({ companyId, iocCount: iocItems.length, feedType }, "automation-dispatcher: upserted IOCs from threat feed");
  }

  // --- 2. Create vulnerability issues for critical/high CVEs ---------------
  const cveItems = (rawItems as IntelItem[]).filter(
    i => i.type === "cve" && i.value && isCriticalOrHigh(i.severity ?? ""),
  );
  if (cveItems.length === 0) return;

  const assigneeId = await findAssignee(db, companyId, "vulnerability_analyst");

  for (const cve of cveItems.slice(0, MAX_CVE_ISSUES_PER_RUN)) {
    const cveId = cve.value || cve.id;
    if (!cveId) continue;

    const existing = await db
      .select({ id: issues.id })
      .from(issues)
      .where(and(eq(issues.companyId, companyId), eq(issues.cveId, cveId)))
      .then(rows => rows[0] ?? null);
    if (existing) continue;

    // Use the actual CVE severity to drive both priority and SLA deadline,
    // rather than hardcoding "high" + 7 days regardless of severity.
    const priority = normalizePriority(cve.severity ?? "high");

    const inserted = await insertIssueAtomic(db, {
      companyId,
      title: `Vulnerability: ${cveId}`,
      description:
        `**Auto-created from threat feed (${feedType})**\n\n` +
        `- CVE: \`${cveId}\`\n` +
        `- Source: ${feedType}\n` +
        `- Severity: ${cve.severity ?? "unknown"}\n` +
        `- Published: ${cve.publishedAt ?? now.toISOString()}\n\n` +
        `*Run: ${runId}*`,
      status: "backlog",
      priority,
      findingType: "vulnerability",
      cveId,
      assigneeAgentId: assigneeId,
      createdByAgentId: agentId,
      slaDeadlineAt: slaDeadline(priority),
    });

    logger.info({ companyId, cveId, feedType, priority }, "automation-dispatcher: created vulnerability issue from threat feed");

    if (inserted?.id && assigneeId) {
      await wakeupAgent?.(assigneeId, inserted.id);
    }
  }
}

// --- Scanner ----------------------------------------------------------------

interface NucleiFinding {
  id?: string;
  templateId?: string;
  name?: string;
  title?: string;
  severity?: string;
  host?: string;
}

async function processScanner(ctx: DispatchContext): Promise<void> {
  const { db, companyId, agentId, runId, resultJson, wakeupAgent } = ctx;

  const tool = String(resultJson.tool ?? "scanner");
  const targets = Array.isArray(resultJson.targets) ? (resultJson.targets as string[]).join(", ") : "unknown";
  const criticalCount = Number(resultJson.criticalCount ?? resultJson.findingCount ?? 0);

  // If we have structured nuclei findings, create per-finding issues
  const rawFindings = Array.isArray(resultJson.findings) ? resultJson.findings : [];
  const criticalFindings = (rawFindings as NucleiFinding[]).filter(f => isCriticalOrHigh(f.severity ?? ""));

  if (criticalFindings.length > 0) {
    const assigneeId = await findAssignee(db, companyId, "vulnerability_analyst");

    for (const finding of criticalFindings.slice(0, MAX_FINDINGS_PER_RUN)) {
      const sourceAlertId = String(finding.id ?? finding.templateId ?? "");
      if (!sourceAlertId) continue;

      const existing = await db
        .select({ id: issues.id })
        .from(issues)
        .where(and(eq(issues.companyId, companyId), eq(issues.sourceAlertId, sourceAlertId)))
        .then(rows => rows[0] ?? null);
      if (existing) continue;

      const priority = normalizePriority(finding.severity ?? "high");

      const inserted = await insertIssueAtomic(db, {
        companyId,
        title: String(finding.name ?? finding.title ?? `Scanner finding: ${sourceAlertId}`),
        description:
          `**Auto-created from ${tool} scan**\n\n` +
          `- Finding: \`${sourceAlertId}\`\n` +
          `- Severity: ${finding.severity}\n` +
          `- Host: ${finding.host ?? "unknown"}\n\n` +
          `*Run: ${runId}*`,
        status: "backlog",
        priority,
        findingType: "vulnerability",
        sourceAlertId,
        assigneeAgentId: assigneeId,
        createdByAgentId: agentId,
        slaDeadlineAt: slaDeadline(priority),
      });

      logger.info({ companyId, sourceAlertId, tool, priority }, "automation-dispatcher: created issue from scanner finding");

      if (inserted?.id && assigneeId) {
        await wakeupAgent?.(assigneeId, inserted.id);
      }
    }
    return;
  }

  // Fall back: create a summary issue if counts are positive but no structured findings
  if (criticalCount === 0) return;

  const assigneeId = await findAssignee(db, companyId, "vulnerability_analyst");
  const priority = "high";

  const inserted = await insertIssueAtomic(db, {
    companyId,
    title: `Scanner Alert: ${criticalCount} critical/high finding(s) [${tool}] against ${targets}`,
    description:
      `**Auto-created from ${tool} scan**\n\n` +
      `- Tool: ${tool}\n` +
      `- Targets: ${targets}\n` +
      `- Critical/High Findings: ${criticalCount}\n\n` +
      `*Run: ${runId}*`,
    status: "backlog",
    priority,
    findingType: "vulnerability",
    assigneeAgentId: assigneeId,
    createdByAgentId: agentId,
    slaDeadlineAt: slaDeadline(priority),
  });

  logger.info({ companyId, tool, criticalCount }, "automation-dispatcher: created summary issue from scanner run");

  if (inserted?.id && assigneeId) {
    await wakeupAgent?.(assigneeId, inserted.id);
  }
}

// --- Public API -------------------------------------------------------------

export interface DispatchContext {
  db: Db;
  companyId: string;
  agentId: string;
  runId: string;
  adapterType: string;
  resultJson: Record<string, unknown>;
  /**
   * Called after each new incident is created so the assigned agent is woken
   * up immediately. Injected from heartbeat.ts to avoid a circular import.
   */
  wakeupAgent?: (assigneeId: string, issueId: string) => Promise<void>;
}

/**
 * Called after every successful cyber-defense adapter run.
 * Errors are caught and logged — they never propagate to the heartbeat caller.
 */
export async function dispatchAdapterResult(ctx: DispatchContext): Promise<void> {
  if (!CYBER_ADAPTER_TYPES.has(ctx.adapterType)) return;

  try {
    switch (ctx.adapterType) {
      case "siem":        await processSiem(ctx);        break;
      case "edr":         await processEdr(ctx);         break;
      case "threat_feed": await processThreatFeed(ctx);  break;
      case "scanner":     await processScanner(ctx);     break;
    }
  } catch (err) {
    // Dispatcher failures must never break the heartbeat run lifecycle
    logger.error({ err, companyId: ctx.companyId, agentId: ctx.agentId, runId: ctx.runId, adapterType: ctx.adapterType }, "automation-dispatcher: unhandled error");
  }
}
