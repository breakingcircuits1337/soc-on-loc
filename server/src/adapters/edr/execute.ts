// SOC-on-LOC — EDR Adapter: Execute
// Polls an EDR platform REST API for recent detections on each watch cycle.
// Supported: CrowdStrike Falcon, SentinelOne, Microsoft Defender for Endpoint, Carbon Black.
// Breaking Circuits LLC — breakingcircuits.com

import type { AdapterExecutionContext, AdapterExecutionResult } from "../types.js";
import { asString, asNumber, asBoolean, parseObject } from "../utils.js";

type EdrPlatform = "crowdstrike" | "sentinelone" | "defender" | "carbonblack" | "custom";

interface EdrDetection {
  id: string;
  title: string;
  severity: string;
  hostname?: string;
  tactic?: string;
  technique?: string;
  timestamp: string;
}

// ---- CrowdStrike Falcon ----
async function fetchCrowdStrike(
  clientId: string, clientSecret: string, cloud: string, limit: number, timeoutMs: number,
): Promise<EdrDetection[]> {
  const baseUrl = cloud === "us-2" ? "https://api.us-2.crowdstrike.com"
    : cloud === "eu-1" ? "https://api.eu-1.crowdstrike.com"
    : "https://api.crowdstrike.com";

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    // OAuth2 token
    const tokenRes = await fetch(`${baseUrl}/oauth2/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: `client_id=${encodeURIComponent(clientId)}&client_secret=${encodeURIComponent(clientSecret)}&grant_type=client_credentials`,
      signal: controller.signal,
    });
    if (!tokenRes.ok) throw new Error(`CrowdStrike OAuth failed: ${tokenRes.status}`);
    const tokenData = await tokenRes.json() as { access_token?: string };
    const token = tokenData.access_token;
    if (!token) throw new Error("CrowdStrike: no access_token in response");

    // Fetch detections
    const detectRes = await fetch(`${baseUrl}/detects/queries/detects/v1?limit=${limit}&sort=first_behavior.desc`, {
      headers: { "Authorization": `Bearer ${token}` },
      signal: controller.signal,
    });
    if (!detectRes.ok) throw new Error(`CrowdStrike detections query failed: ${detectRes.status}`);
    const detectData = await detectRes.json() as { resources?: string[] };
    const ids = detectData.resources ?? [];
    if (ids.length === 0) return [];

    const detailRes = await fetch(`${baseUrl}/detects/entities/summaries/GET/v1`, {
      method: "POST",
      headers: { "Authorization": `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ ids }),
      signal: controller.signal,
    });
    if (!detailRes.ok) throw new Error(`CrowdStrike detection details failed: ${detailRes.status}`);
    const detailData = await detailRes.json() as { resources?: Array<Record<string, unknown>> };

    return (detailData.resources ?? []).map(d => ({
      id: String(d["detection_id"] ?? d["id"] ?? ""),
      title: String(d["display_name"] ?? d["description"] ?? "CrowdStrike Detection"),
      severity: String(d["max_severity_displayname"] ?? d["severity"] ?? "unknown"),
      hostname: String(d["device"] && typeof d["device"] === "object" ? (d["device"] as Record<string, unknown>)["hostname"] ?? "" : ""),
      tactic: String(d["tactic"] ?? ""),
      technique: String(d["technique"] ?? ""),
      timestamp: String(d["first_behavior"] ?? d["created_timestamp"] ?? new Date().toISOString()),
    }));
  } finally {
    clearTimeout(timer);
  }
}

// ---- SentinelOne ----
async function fetchSentinelOne(url: string, apiKey: string, limit: number, timeoutMs: number): Promise<EdrDetection[]> {
  const base = url.replace(/\/$/, "");
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`${base}/web/api/v2.1/threats?limit=${limit}&sortBy=createdAt&sortOrder=desc`, {
      headers: { "Authorization": `ApiToken ${apiKey}` },
      signal: controller.signal,
    });
    if (!res.ok) throw new Error(`SentinelOne API returned HTTP ${res.status}`);
    const data = await res.json() as { data?: Array<Record<string, unknown>> };
    return (data.data ?? []).map(d => ({
      id: String(d["id"] ?? ""),
      title: String(d["threatInfo"] && typeof d["threatInfo"] === "object"
        ? (d["threatInfo"] as Record<string, unknown>)["threatName"] ?? "SentinelOne Threat" : "SentinelOne Threat"),
      severity: String(d["threatInfo"] && typeof d["threatInfo"] === "object"
        ? (d["threatInfo"] as Record<string, unknown>)["confidenceLevel"] ?? "unknown" : "unknown"),
      hostname: String(d["agentRealtimeInfo"] && typeof d["agentRealtimeInfo"] === "object"
        ? (d["agentRealtimeInfo"] as Record<string, unknown>)["agentComputerName"] ?? "" : ""),
      timestamp: String(d["createdAt"] ?? new Date().toISOString()),
    }));
  } finally {
    clearTimeout(timer);
  }
}

// ---- Generic / custom REST ----
async function fetchCustomEdr(url: string, headers: Record<string, string>, limit: number, timeoutMs: number): Promise<EdrDetection[]> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const pollUrl = new URL(url);
  pollUrl.searchParams.set("limit", String(limit));
  try {
    const res = await fetch(pollUrl.toString(), { headers, signal: controller.signal });
    if (!res.ok) throw new Error(`EDR endpoint returned HTTP ${res.status}`);
    const data = await res.json() as unknown;
    const arr: unknown[] = Array.isArray(data) ? data :
      (data && typeof data === "object" ? Object.values(data as Record<string, unknown>).find(v => Array.isArray(v)) as unknown[] ?? [] : []);
    return arr.slice(0, limit).map((item, i) => {
      if (item && typeof item === "object") {
        const d = item as Record<string, unknown>;
        return {
          id: String(d["id"] ?? `edr-${i}`),
          title: String(d["title"] ?? d["name"] ?? d["threat_name"] ?? "EDR Detection"),
          severity: String(d["severity"] ?? d["confidence"] ?? "unknown"),
          hostname: String(d["hostname"] ?? d["host"] ?? ""),
          tactic: String(d["tactic"] ?? ""),
          technique: String(d["technique"] ?? ""),
          timestamp: String(d["timestamp"] ?? d["created_at"] ?? new Date().toISOString()),
        };
      }
      return { id: `edr-${i}`, title: String(item), severity: "unknown", timestamp: new Date().toISOString() };
    });
  } finally {
    clearTimeout(timer);
  }
}

export async function execute(ctx: AdapterExecutionContext): Promise<AdapterExecutionResult> {
  const { config } = ctx;

  const platform = asString(config.platform, "custom") as EdrPlatform;
  const apiKey = asString(config.apiKey, "");
  const url = asString(config.url, "");
  const limit = asNumber(config.limit, 50);
  const timeoutMs = asNumber(config.timeoutMs, 15000);
  const dryRun = asBoolean(config.dryRun, false);
  const extraHeaders = parseObject(config.headers) as Record<string, string>;

  if (dryRun) {
    return { exitCode: 0, signal: null, timedOut: false, summary: `EDR dry-run (${platform}) — no detections fetched` };
  }

  let detections: EdrDetection[] = [];

  switch (platform) {
    case "crowdstrike": {
      const clientId = asString(config.clientId, "");
      const clientSecret = asString(config.clientSecret, "");
      const cloud = asString(config.cloud, "us-1");
      if (!clientId || !clientSecret) throw new Error("CrowdStrike adapter requires clientId and clientSecret");
      detections = await fetchCrowdStrike(clientId, clientSecret, cloud, limit, timeoutMs);
      break;
    }
    case "sentinelone": {
      if (!url) throw new Error("SentinelOne adapter requires url");
      if (!apiKey) throw new Error("SentinelOne adapter requires apiKey");
      detections = await fetchSentinelOne(url, apiKey, limit, timeoutMs);
      break;
    }
    case "defender":
    case "carbonblack":
    case "custom":
    default: {
      if (!url) throw new Error(`${platform} adapter requires url`);
      const headers: Record<string, string> = { ...extraHeaders };
      if (apiKey) headers["Authorization"] = `Bearer ${apiKey}`;
      detections = await fetchCustomEdr(url, headers, limit, timeoutMs);
      break;
    }
  }

  const criticalCount = detections.filter(d => /critical|high/i.test(d.severity)).length;
  const summary = detections.length === 0
    ? `EDR (${platform}): no new detections`
    : `EDR (${platform}): ${detections.length} detection(s) — ${criticalCount} critical/high`;

  return {
    exitCode: 0,
    signal: null,
    timedOut: false,
    summary,
    // Include capped detections array so automation-dispatcher can create per-detection incidents
    resultJson: { platform, detectionCount: detections.length, criticalCount, detections: detections.slice(0, 50) },
  };
}
