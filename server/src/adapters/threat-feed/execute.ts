// SOC-on-LOC — Threat Feed Adapter: Execute
// Polls external threat intelligence sources (NVD, OTX, MISP, STIX-TAXII, VirusTotal, Shodan).
// Returns a structured summary of new IOCs and CVEs for the intel_analyst defender agent.
// Breaking Circuits LLC — breakingcircuits.com

import type { AdapterExecutionContext, AdapterExecutionResult } from "../types.js";
import { asString, asNumber, asBoolean, parseObject } from "../utils.js";

type FeedType = "nvd" | "otx" | "misp" | "stix_taxii" | "vt" | "shodan" | "custom";

interface IntelItem {
  id: string;
  type: string;       // ioc type or "cve"
  value: string;
  severity?: string;
  source: string;
  publishedAt?: string;
}

// ---- NVD CVE feed (NIST) ----
async function fetchNvd(apiKey: string, lookbackDays: number, timeoutMs: number): Promise<IntelItem[]> {
  const since = new Date(Date.now() - lookbackDays * 86400000).toISOString();
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${since}&resultsPerPage=100`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const headers: Record<string, string> = {};
    if (apiKey) headers["apiKey"] = apiKey;
    const res = await fetch(url, { headers, signal: controller.signal });
    if (!res.ok) throw new Error(`NVD returned HTTP ${res.status}`);
    const data = await res.json() as { vulnerabilities?: Array<{ cve: { id: string; metrics?: Record<string, unknown>; descriptions?: Array<{ lang: string; value: string }> } }> };
    return (data.vulnerabilities ?? []).map(v => ({
      id: v.cve.id,
      type: "cve",
      value: v.cve.id,
      severity: "unknown",
      source: "nvd",
      publishedAt: since,
    }));
  } finally {
    clearTimeout(timer);
  }
}

// ---- AlienVault OTX ----
async function fetchOtx(apiKey: string, lookbackDays: number, timeoutMs: number): Promise<IntelItem[]> {
  const url = `https://otx.alienvault.com/api/v1/pulses/subscribed?modified_since=${lookbackDays}d&limit=100`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      headers: { "X-OTX-API-KEY": apiKey },
      signal: controller.signal,
    });
    if (!res.ok) throw new Error(`OTX returned HTTP ${res.status}`);
    const data = await res.json() as { results?: Array<{ indicators?: Array<{ type: string; indicator: string }> }> };
    const items: IntelItem[] = [];
    for (const pulse of data.results ?? []) {
      for (const ind of pulse.indicators ?? []) {
        items.push({ id: `otx-${ind.indicator}`, type: ind.type, value: ind.indicator, source: "otx" });
      }
    }
    return items.slice(0, 200);
  } finally {
    clearTimeout(timer);
  }
}

// ---- MISP ----
async function fetchMisp(url: string, apiKey: string, lookbackDays: number, timeoutMs: number): Promise<IntelItem[]> {
  const since = Math.floor((Date.now() - lookbackDays * 86400000) / 1000);
  const searchUrl = `${url.replace(/\/$/, "")}/attributes/restSearch`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(searchUrl, {
      method: "POST",
      headers: { "Authorization": apiKey, "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify({ returnFormat: "json", timestamp: since, limit: 200 }),
      signal: controller.signal,
    });
    if (!res.ok) throw new Error(`MISP returned HTTP ${res.status}`);
    const data = await res.json() as { response?: { Attribute?: Array<{ id: string; type: string; value: string }> } };
    return (data.response?.Attribute ?? []).map(a => ({
      id: `misp-${a.id}`,
      type: a.type,
      value: a.value,
      source: "misp",
    }));
  } finally {
    clearTimeout(timer);
  }
}

// ---- Custom / generic REST feed ----
async function fetchCustom(url: string, headers: Record<string, string>, timeoutMs: number): Promise<IntelItem[]> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { headers, signal: controller.signal });
    if (!res.ok) throw new Error(`Custom feed returned HTTP ${res.status}`);
    const data = await res.json() as unknown;
    const arr = Array.isArray(data) ? data :
      (data && typeof data === "object" ? Object.values(data as Record<string, unknown>).find(v => Array.isArray(v)) as unknown[] ?? [] : []);
    return arr.slice(0, 500).map((item, i) => ({
      id: `custom-${i}`,
      type: "unknown",
      value: typeof item === "string" ? item : JSON.stringify(item),
      source: "custom",
    }));
  } finally {
    clearTimeout(timer);
  }
}

export async function execute(ctx: AdapterExecutionContext): Promise<AdapterExecutionResult> {
  const { config } = ctx;

  const feedType = asString(config.feedType, "custom") as FeedType;
  const apiKey = asString(config.apiKey, "");
  const url = asString(config.url, "");
  const lookbackDays = asNumber(config.lookbackDays, 1);
  const timeoutMs = asNumber(config.timeoutMs, 15000);
  const dryRun = asBoolean(config.dryRun, false);
  const extraHeaders = parseObject(config.headers) as Record<string, string>;

  if (dryRun) {
    return { exitCode: 0, signal: null, timedOut: false, summary: `Threat feed dry-run (${feedType}) — no data fetched` };
  }

  let items: IntelItem[] = [];

  switch (feedType) {
    case "nvd":
      items = await fetchNvd(apiKey, lookbackDays, timeoutMs);
      break;
    case "otx":
      if (!apiKey) throw new Error("OTX feed requires apiKey");
      items = await fetchOtx(apiKey, lookbackDays, timeoutMs);
      break;
    case "misp":
      if (!url) throw new Error("MISP feed requires url");
      if (!apiKey) throw new Error("MISP feed requires apiKey");
      items = await fetchMisp(url, apiKey, lookbackDays, timeoutMs);
      break;
    case "custom":
    case "stix_taxii":
    case "vt":
    case "shodan":
    default: {
      if (!url) throw new Error(`${feedType} feed requires url`);
      const headers: Record<string, string> = { ...extraHeaders };
      if (apiKey) headers["Authorization"] = `Bearer ${apiKey}`;
      items = await fetchCustom(url, headers, timeoutMs);
      break;
    }
  }

  const cveCount = items.filter(i => i.type === "cve").length;
  const iocCount = items.length - cveCount;
  const summary = items.length === 0
    ? `Threat feed (${feedType}): no new intelligence`
    : `Threat feed (${feedType}): ${items.length} item(s) — ${cveCount} CVEs, ${iocCount} IOCs`;

  return {
    exitCode: 0,
    signal: null,
    timedOut: false,
    summary,
    resultJson: { feedType, totalItems: items.length, cveCount, iocCount },
  };
}
