// SOC-on-LOC — EDR Adapter: Environment Test
// Breaking Circuits LLC — breakingcircuits.com

import type {
  AdapterEnvironmentCheck,
  AdapterEnvironmentTestContext,
  AdapterEnvironmentTestResult,
} from "../types.js";
import { asString, parseObject } from "../utils.js";

function summarize(checks: AdapterEnvironmentCheck[]): AdapterEnvironmentTestResult["status"] {
  if (checks.some((c) => c.level === "error")) return "fail";
  if (checks.some((c) => c.level === "warn")) return "warn";
  return "pass";
}

export async function testEnvironment(
  ctx: AdapterEnvironmentTestContext,
): Promise<AdapterEnvironmentTestResult> {
  const checks: AdapterEnvironmentCheck[] = [];
  const config = parseObject(ctx.config);

  const platform = asString(config.platform, "custom");
  const apiKey = asString(config.apiKey, "");
  const url = asString(config.url, "");
  const clientId = asString(config.clientId, "");
  const clientSecret = asString(config.clientSecret, "");

  checks.push({ code: "edr_platform", level: "info", message: `EDR platform: ${platform}` });

  switch (platform) {
    case "crowdstrike":
      if (!clientId) {
        checks.push({ code: "edr_cs_clientid_missing", level: "error", message: "CrowdStrike requires adapterConfig.clientId", hint: "Generate an API client in CrowdStrike Falcon console." });
      } else {
        checks.push({ code: "edr_cs_clientid_set", level: "info", message: "clientId configured." });
      }
      if (!clientSecret) {
        checks.push({ code: "edr_cs_secret_missing", level: "error", message: "CrowdStrike requires adapterConfig.clientSecret" });
      } else {
        checks.push({ code: "edr_cs_secret_set", level: "info", message: "clientSecret configured." });
      }
      break;

    case "sentinelone":
      if (!url) {
        checks.push({ code: "edr_s1_url_missing", level: "error", message: "SentinelOne requires adapterConfig.url", hint: "Set to your SentinelOne management console URL." });
      } else {
        try { new URL(url); checks.push({ code: "edr_s1_url_valid", level: "info", message: `URL: ${url}` }); }
        catch { checks.push({ code: "edr_s1_url_invalid", level: "error", message: `Invalid URL: ${url}` }); }
      }
      if (!apiKey) {
        checks.push({ code: "edr_s1_apikey_missing", level: "error", message: "SentinelOne requires adapterConfig.apiKey", hint: "Generate an API token in SentinelOne User Management." });
      } else {
        checks.push({ code: "edr_s1_apikey_set", level: "info", message: "API key configured." });
      }
      break;

    default:
      if (!url) {
        checks.push({ code: "edr_url_missing", level: "error", message: `${platform} platform requires adapterConfig.url` });
      } else {
        try { new URL(url); checks.push({ code: "edr_url_valid", level: "info", message: `Endpoint: ${url}` }); }
        catch { checks.push({ code: "edr_url_invalid", level: "error", message: `Invalid URL: ${url}` }); }
      }
      if (!apiKey) {
        checks.push({ code: "edr_apikey_missing", level: "warn", message: "No apiKey configured — requests will be unauthenticated." });
      } else {
        checks.push({ code: "edr_apikey_set", level: "info", message: "API key configured." });
      }
  }

  return { adapterType: ctx.adapterType, status: summarize(checks), checks, testedAt: new Date().toISOString() };
}
