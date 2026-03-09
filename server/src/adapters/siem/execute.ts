// SOC-on-LOC — SIEM Adapter: Execute
// Polls a SIEM REST API for recent alerts on each watch cycle.
// Supported platforms: Splunk, Elastic SIEM, Microsoft Sentinel, QRadar, generic REST.
// Breaking Circuits LLC — breakingcircuits.com

import type { AdapterExecutionContext, AdapterExecutionResult } from "../types.js";
import { asString, asNumber, asBoolean, parseObject } from "../utils.js";

interface SiemAlert {
  id: string;
  title: string;
  severity: string;
  timestamp: string;
  raw?: unknown;
}

async function fetchAlerts(
  url: string,
  headers: Record<string, string>,
  timeoutMs: number,
  limitParam: string,
  limit: number,
): Promise<SiemAlert[]> {
  const controller = new AbortController();
  const timer = timeoutMs > 0 ? setTimeout(() => controller.abort(), timeoutMs) : null;

  const pollUrl = new URL(url);
  if (limitParam) pollUrl.searchParams.set(limitParam, String(limit));

  try {
    const res = await fetch(pollUrl.toString(), {
      headers: { "content-type": "application/json", ...headers },
      signal: controller.signal,
    });
    if (!res.ok) throw new Error(`SIEM API returned HTTP ${res.status}`);
    const data = await res.json() as unknown;

    // Normalise: accept array directly or { alerts: [...] } / { hits: [...] } envelope
    let raw: unknown[] = [];
    if (Array.isArray(data)) {
      raw = data;
    } else if (data && typeof data === "object") {
      const obj = data as Record<string, unknown>;
      raw = (Array.isArray(obj["alerts"]) ? obj["alerts"] :
             Array.isArray(obj["hits"]) ? obj["hits"] :
             Array.isArray(obj["events"]) ? obj["events"] :
             Array.isArray(obj["results"]) ? obj["results"] : []) as unknown[];
    }

    return raw.slice(0, limit).map((item, i) => {
      if (item && typeof item === "object") {
        const a = item as Record<string, unknown>;
        return {
          id: String(a["id"] ?? a["_id"] ?? a["alert_id"] ?? `alert-${i}`),
          title: String(a["title"] ?? a["name"] ?? a["message"] ?? "Unnamed alert"),
          severity: String(a["severity"] ?? a["level"] ?? a["priority"] ?? "unknown"),
          timestamp: String(a["timestamp"] ?? a["@timestamp"] ?? a["created_at"] ?? new Date().toISOString()),
          raw: item,
        };
      }
      return { id: `alert-${i}`, title: String(item), severity: "unknown", timestamp: new Date().toISOString() };
    });
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export async function execute(ctx: AdapterExecutionContext): Promise<AdapterExecutionResult> {
  const { config } = ctx;

  const url = asString(config.url, "");
  if (!url) throw new Error("SIEM adapter: url is required");

  const rawHeaders = parseObject(config.headers) as Record<string, string>;
  const apiKey = asString(config.apiKey, "");
  const authHeader = asString(config.authHeader, "Authorization");
  const authPrefix = asString(config.authPrefix, "Bearer");
  const timeoutMs = asNumber(config.timeoutMs, 10000);
  const limit = asNumber(config.limit, 50);
  const limitParam = asString(config.limitParam, "limit");
  const dryRun = asBoolean(config.dryRun, false);

  const headers: Record<string, string> = { ...rawHeaders };
  if (apiKey) headers[authHeader] = `${authPrefix} ${apiKey}`.trim();

  if (dryRun) {
    return {
      exitCode: 0,
      signal: null,
      timedOut: false,
      summary: "SIEM adapter dry-run — no alerts fetched",
    };
  }

  const alerts = await fetchAlerts(url, headers, timeoutMs, limitParam, limit);

  const criticalCount = alerts.filter(a => /critical|high/i.test(a.severity)).length;
  const summary = alerts.length === 0
    ? "SIEM poll: no new alerts"
    : `SIEM poll: ${alerts.length} alert(s) — ${criticalCount} critical/high`;

  return {
    exitCode: 0,
    signal: null,
    timedOut: false,
    summary,
    resultJson: { alertCount: alerts.length, criticalCount, alerts },
  };
}
