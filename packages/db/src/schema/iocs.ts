// SOC-on-LOC — Indicators of Compromise
// Breaking Circuits LLC — breakingcircuits.com

import {
  pgTable,
  uuid,
  text,
  timestamp,
  boolean,
  jsonb,
  index,
  uniqueIndex,
} from "drizzle-orm/pg-core";
import { companies } from "./companies.js";

export const iocs = pgTable(
  "iocs",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    companyId: uuid("company_id").notNull().references(() => companies.id),

    // Core IOC data
    iocType: text("ioc_type").notNull(),        // IOC_TYPES constant
    value: text("value").notNull(),             // The actual indicator value
    confidence: text("confidence").notNull().default("unknown"), // IOC_CONFIDENCE_LEVELS

    // Attribution
    threatActor: text("threat_actor"),          // Known threat actor attribution
    malwareFamily: text("malware_family"),       // Malware family association
    campaign: text("campaign"),                 // Campaign name
    tags: jsonb("tags").$type<string[]>().default([]),

    // Intel source
    sourceType: text("source_type"),            // THREAT_FEED_TYPES constant
    sourceName: text("source_name"),            // Human-readable source name
    sourceReference: text("source_reference"),  // URL or external ID

    // MITRE mapping
    mitreTactic: text("mitre_tactic"),          // MITRE_TACTICS constant
    mitreTechnique: text("mitre_technique"),    // T1234 style technique ID

    // Lifecycle
    isActive: boolean("is_active").notNull().default(true),
    firstSeenAt: timestamp("first_seen_at", { withTimezone: true }),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true }),
    expiresAt: timestamp("expires_at", { withTimezone: true }),

    // Extended
    metadata: jsonb("metadata").$type<Record<string, unknown>>(),
    notes: text("notes"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    companyTypeIdx: index("iocs_company_type_idx").on(table.companyId, table.iocType),
    companyActiveIdx: index("iocs_company_active_idx").on(table.companyId, table.isActive),
    companyValueUq: uniqueIndex("iocs_company_type_value_uq").on(table.companyId, table.iocType, table.value),
    confidenceIdx: index("iocs_confidence_idx").on(table.companyId, table.confidence),
  }),
);
