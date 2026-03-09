// SOC-on-LOC — Incidents / Findings (extended from paperclip issues)
// Breaking Circuits LLC — breakingcircuits.com

import {
  type AnyPgColumn,
  pgTable,
  uuid,
  text,
  timestamp,
  integer,
  real,
  jsonb,
  index,
  uniqueIndex,
} from "drizzle-orm/pg-core";
import { agents } from "./agents.js";
import { projects } from "./projects.js";
import { goals } from "./goals.js";
import { companies } from "./companies.js";
import { heartbeatRuns } from "./heartbeat_runs.js";

export const issues = pgTable(
  "issues",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    companyId: uuid("company_id").notNull().references(() => companies.id),
    projectId: uuid("project_id").references(() => projects.id),
    goalId: uuid("goal_id").references(() => goals.id),
    parentId: uuid("parent_id").references((): AnyPgColumn => issues.id),
    title: text("title").notNull(),
    description: text("description"),
    status: text("status").notNull().default("backlog"),
    priority: text("priority").notNull().default("medium"),
    assigneeAgentId: uuid("assignee_agent_id").references(() => agents.id),
    assigneeUserId: text("assignee_user_id"),
    checkoutRunId: uuid("checkout_run_id").references(() => heartbeatRuns.id, { onDelete: "set null" }),
    executionRunId: uuid("execution_run_id").references(() => heartbeatRuns.id, { onDelete: "set null" }),
    executionAgentNameKey: text("execution_agent_name_key"),
    executionLockedAt: timestamp("execution_locked_at", { withTimezone: true }),
    createdByAgentId: uuid("created_by_agent_id").references(() => agents.id),
    createdByUserId: text("created_by_user_id"),
    issueNumber: integer("issue_number"),
    identifier: text("identifier"),
    requestDepth: integer("request_depth").notNull().default(0),
    billingCode: text("billing_code"),
    assigneeAdapterOverrides: jsonb("assignee_adapter_overrides").$type<Record<string, unknown>>(),
    startedAt: timestamp("started_at", { withTimezone: true }),
    completedAt: timestamp("completed_at", { withTimezone: true }),
    cancelledAt: timestamp("cancelled_at", { withTimezone: true }),
    hiddenAt: timestamp("hidden_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),

    // --- SOC-on-LOC Cyber Defense Extensions ---

    // Finding metadata
    findingType: text("finding_type"),                // FINDING_TYPES constant
    sourceAlertId: text("source_alert_id"),           // External SIEM/EDR alert ID

    // CVE / Vulnerability fields
    cveId: text("cve_id"),                            // CVE-YYYY-NNNNN
    cvssScore: real("cvss_score"),                    // 0.0 – 10.0
    cvssVector: text("cvss_vector"),                  // CVSS vector string

    // MITRE ATT&CK
    mitreTactic: text("mitre_tactic"),                // MITRE_TACTICS constant (TA0001...)
    mitreTechnique: text("mitre_technique"),          // T1234 or T1234.001
    killChainStage: text("kill_chain_stage"),         // KILL_CHAIN_STAGES constant

    // Asset and IOC linkage (denormalized for query performance)
    affectedAssetIds: jsonb("affected_asset_ids").$type<string[]>().default([]),
    iocIds: jsonb("ioc_ids").$type<string[]>().default([]),

    // SLA and timing metrics
    slaDeadlineAt: timestamp("sla_deadline_at", { withTimezone: true }),
    mttdSeconds: integer("mttd_seconds"),              // Mean time to detect
    mttrSeconds: integer("mttr_seconds"),              // Mean time to respond/remediate

    // Containment actions taken
    containmentActions: jsonb("containment_actions").$type<
      Array<{
        actionType: string;   // CONTAINMENT_ACTION_TYPES constant
        performedAt: string;  // ISO timestamp
        performedBy: string;  // agent ID or user ID
        details: string;
      }>
    >().default([]),

    // Evidence artifacts
    evidence: jsonb("evidence").$type<
      Array<{
        type: string;         // log, screenshot, pcap, memory_dump, file
        label: string;
        reference: string;    // file path, URL, or asset ID
        collectedAt: string;
      }>
    >().default([]),
  },
  (table) => ({
    companyStatusIdx: index("issues_company_status_idx").on(table.companyId, table.status),
    assigneeStatusIdx: index("issues_company_assignee_status_idx").on(
      table.companyId,
      table.assigneeAgentId,
      table.status,
    ),
    assigneeUserStatusIdx: index("issues_company_assignee_user_status_idx").on(
      table.companyId,
      table.assigneeUserId,
      table.status,
    ),
    parentIdx: index("issues_company_parent_idx").on(table.companyId, table.parentId),
    projectIdx: index("issues_company_project_idx").on(table.companyId, table.projectId),
    identifierIdx: uniqueIndex("issues_identifier_idx").on(table.identifier),
  }),
);
