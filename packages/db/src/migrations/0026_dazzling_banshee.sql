CREATE TABLE "iocs" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"company_id" uuid NOT NULL,
	"ioc_type" text NOT NULL,
	"value" text NOT NULL,
	"confidence" text DEFAULT 'unknown' NOT NULL,
	"threat_actor" text,
	"malware_family" text,
	"campaign" text,
	"tags" jsonb DEFAULT '[]'::jsonb,
	"source_type" text,
	"source_name" text,
	"source_reference" text,
	"mitre_tactic" text,
	"mitre_technique" text,
	"is_active" boolean DEFAULT true NOT NULL,
	"first_seen_at" timestamp with time zone,
	"last_seen_at" timestamp with time zone,
	"expires_at" timestamp with time zone,
	"metadata" jsonb,
	"notes" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "network_assets" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"company_id" uuid NOT NULL,
	"hostname" text,
	"fqdn" text,
	"ip_address" text,
	"mac_address" text,
	"asset_type" text DEFAULT 'unknown' NOT NULL,
	"criticality" text DEFAULT 'medium' NOT NULL,
	"owner" text,
	"environment" text,
	"operating_system" text,
	"os_version" text,
	"location" text,
	"status" text DEFAULT 'active' NOT NULL,
	"first_seen_at" timestamp with time zone,
	"last_seen_at" timestamp with time zone,
	"tags" jsonb DEFAULT '[]'::jsonb,
	"metadata" jsonb,
	"notes" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "threat_feeds" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"company_id" uuid NOT NULL,
	"name" text NOT NULL,
	"feed_type" text NOT NULL,
	"description" text,
	"url" text,
	"api_key_secret_id" uuid,
	"is_enabled" boolean DEFAULT true NOT NULL,
	"poll_interval_minutes" integer DEFAULT 60 NOT NULL,
	"last_polled_at" timestamp with time zone,
	"last_success_at" timestamp with time zone,
	"last_error_at" timestamp with time zone,
	"last_error_message" text,
	"total_iocs_ingested" integer DEFAULT 0 NOT NULL,
	"config" jsonb,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "issues" ADD COLUMN "finding_type" text;--> statement-breakpoint
ALTER TABLE "issues" ADD COLUMN "source_alert_id" text;--> statement-breakpoint
ALTER TABLE "issues" ADD COLUMN "cve_id" text;--> statement-breakpoint
ALTER TABLE "issues" ADD COLUMN "cvss_score" real;--> statement-breakpoint
ALTER TABLE "issues" ADD COLUMN "cvss_vector" text;--> statement-breakpoint
ALTER TABLE "issues" ADD COLUMN "mitre_tactic" text;--> statement-breakpoint
ALTER TABLE "issues" ADD COLUMN "mitre_technique" text;--> statement-breakpoint
ALTER TABLE "issues" ADD COLUMN "kill_chain_stage" text;--> statement-breakpoint
ALTER TABLE "issues" ADD COLUMN "affected_asset_ids" jsonb DEFAULT '[]'::jsonb;--> statement-breakpoint
ALTER TABLE "issues" ADD COLUMN "ioc_ids" jsonb DEFAULT '[]'::jsonb;--> statement-breakpoint
ALTER TABLE "issues" ADD COLUMN "sla_deadline_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "issues" ADD COLUMN "mttd_seconds" integer;--> statement-breakpoint
ALTER TABLE "issues" ADD COLUMN "mttr_seconds" integer;--> statement-breakpoint
ALTER TABLE "issues" ADD COLUMN "containment_actions" jsonb DEFAULT '[]'::jsonb;--> statement-breakpoint
ALTER TABLE "issues" ADD COLUMN "evidence" jsonb DEFAULT '[]'::jsonb;--> statement-breakpoint
ALTER TABLE "iocs" ADD CONSTRAINT "iocs_company_id_companies_id_fk" FOREIGN KEY ("company_id") REFERENCES "public"."companies"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "network_assets" ADD CONSTRAINT "network_assets_company_id_companies_id_fk" FOREIGN KEY ("company_id") REFERENCES "public"."companies"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "threat_feeds" ADD CONSTRAINT "threat_feeds_company_id_companies_id_fk" FOREIGN KEY ("company_id") REFERENCES "public"."companies"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "iocs_company_type_idx" ON "iocs" USING btree ("company_id","ioc_type");--> statement-breakpoint
CREATE INDEX "iocs_company_active_idx" ON "iocs" USING btree ("company_id","is_active");--> statement-breakpoint
CREATE UNIQUE INDEX "iocs_company_type_value_uq" ON "iocs" USING btree ("company_id","ioc_type","value");--> statement-breakpoint
CREATE INDEX "iocs_confidence_idx" ON "iocs" USING btree ("company_id","confidence");--> statement-breakpoint
CREATE INDEX "network_assets_company_type_idx" ON "network_assets" USING btree ("company_id","asset_type");--> statement-breakpoint
CREATE INDEX "network_assets_company_status_idx" ON "network_assets" USING btree ("company_id","status");--> statement-breakpoint
CREATE INDEX "network_assets_company_ip_idx" ON "network_assets" USING btree ("company_id","ip_address");--> statement-breakpoint
CREATE INDEX "network_assets_company_criticality_idx" ON "network_assets" USING btree ("company_id","criticality");--> statement-breakpoint
CREATE INDEX "threat_feeds_company_type_idx" ON "threat_feeds" USING btree ("company_id","feed_type");--> statement-breakpoint
CREATE INDEX "threat_feeds_company_enabled_idx" ON "threat_feeds" USING btree ("company_id","is_enabled");