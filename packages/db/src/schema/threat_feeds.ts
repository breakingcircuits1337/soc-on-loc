// SOC-on-LOC — Threat Feed Registry
// Breaking Circuits LLC — breakingcircuits.com

import {
  pgTable,
  uuid,
  text,
  timestamp,
  boolean,
  integer,
  jsonb,
  index,
} from "drizzle-orm/pg-core";
import { companies } from "./companies.js";

export const threatFeeds = pgTable(
  "threat_feeds",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    companyId: uuid("company_id").notNull().references(() => companies.id),

    // Identity
    name: text("name").notNull(),
    feedType: text("feed_type").notNull(),         // THREAT_FEED_TYPES constant
    description: text("description"),

    // Connection
    url: text("url"),                              // Feed endpoint URL
    apiKeySecretId: uuid("api_key_secret_id"),     // Reference to company_secrets

    // Poll settings
    isEnabled: boolean("is_enabled").notNull().default(true),
    pollIntervalMinutes: integer("poll_interval_minutes").notNull().default(60),

    // Status tracking
    lastPolledAt: timestamp("last_polled_at", { withTimezone: true }),
    lastSuccessAt: timestamp("last_success_at", { withTimezone: true }),
    lastErrorAt: timestamp("last_error_at", { withTimezone: true }),
    lastErrorMessage: text("last_error_message"),
    totalIocsIngested: integer("total_iocs_ingested").notNull().default(0),

    // Filter / config
    config: jsonb("config").$type<Record<string, unknown>>(),

    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    companyTypeIdx: index("threat_feeds_company_type_idx").on(table.companyId, table.feedType),
    companyEnabledIdx: index("threat_feeds_company_enabled_idx").on(table.companyId, table.isEnabled),
  }),
);
