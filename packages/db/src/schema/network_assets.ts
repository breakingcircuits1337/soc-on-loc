// SOC-on-LOC — Network Asset Inventory
// Breaking Circuits LLC — breakingcircuits.com

import {
  pgTable,
  uuid,
  text,
  timestamp,
  jsonb,
  index,
} from "drizzle-orm/pg-core";
import { companies } from "./companies.js";

export const networkAssets = pgTable(
  "network_assets",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    companyId: uuid("company_id").notNull().references(() => companies.id),

    // Identity
    hostname: text("hostname"),
    fqdn: text("fqdn"),
    ipAddress: text("ip_address"),
    macAddress: text("mac_address"),
    assetType: text("asset_type").notNull().default("unknown"),       // ASSET_TYPES constant
    criticality: text("criticality").notNull().default("medium"),     // ASSET_CRITICALITY constant

    // Classification
    owner: text("owner"),                                             // Team/person responsible
    environment: text("environment"),                                 // prod, staging, dev, corp
    operatingSystem: text("operating_system"),
    osVersion: text("os_version"),
    location: text("location"),                                       // DC rack, cloud region, office

    // Status
    status: text("status").notNull().default("active"),               // active, decommissioned, unknown
    firstSeenAt: timestamp("first_seen_at", { withTimezone: true }),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true }),

    // Tags and extended metadata
    tags: jsonb("tags").$type<string[]>().default([]),
    metadata: jsonb("metadata").$type<Record<string, unknown>>(),

    notes: text("notes"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    companyTypeIdx: index("network_assets_company_type_idx").on(table.companyId, table.assetType),
    companyStatusIdx: index("network_assets_company_status_idx").on(table.companyId, table.status),
    companyIpIdx: index("network_assets_company_ip_idx").on(table.companyId, table.ipAddress),
    companyCriticalityIdx: index("network_assets_company_criticality_idx").on(table.companyId, table.criticality),
  }),
);
