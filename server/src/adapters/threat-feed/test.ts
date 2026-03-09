// SOC-on-LOC — Threat Feed Adapter: Environment Test
// Breaking Circuits LLC — breakingcircuits.com

import type {
  AdapterEnvironmentCheck,
  AdapterEnvironmentTestContext,
  AdapterEnvironmentTestResult,
} from "../types.js";
import { asString, parseObject } from "../utils.js";

const FEEDS_REQUIRING_URL = new Set(["misp", "stix_taxii", "vt", "shodan", "custom"]);
const FEEDS_REQUIRING_KEY = new Set(["otx", "misp", "vt", "shodan"]);

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

  const feedType = asString(config.feedType, "custom");
  const apiKey = asString(config.apiKey, "");
  const urlValue = asString(config.url, "");

  checks.push({ code: "threat_feed_type", level: "info", message: `Feed type: ${feedType}` });

  if (FEEDS_REQUIRING_URL.has(feedType) && !urlValue) {
    checks.push({
      code: "threat_feed_url_missing",
      level: "error",
      message: `Feed type "${feedType}" requires a url.`,
      hint: `Set adapterConfig.url to your ${feedType.toUpperCase()} endpoint.`,
    });
  } else if (urlValue) {
    try {
      new URL(urlValue);
      checks.push({ code: "threat_feed_url_valid", level: "info", message: `Endpoint: ${urlValue}` });
    } catch {
      checks.push({ code: "threat_feed_url_invalid", level: "error", message: `Invalid URL: ${urlValue}` });
    }
  }

  if (FEEDS_REQUIRING_KEY.has(feedType) && !apiKey) {
    checks.push({
      code: "threat_feed_apikey_missing",
      level: "error",
      message: `Feed type "${feedType}" requires an apiKey.`,
      hint: `Set adapterConfig.apiKey to your ${feedType.toUpperCase()} API key.`,
    });
  } else if (apiKey) {
    checks.push({ code: "threat_feed_apikey_present", level: "info", message: "API key configured." });
  }

  // NVD works without key but rate-limits heavily
  if (feedType === "nvd" && !apiKey) {
    checks.push({
      code: "threat_feed_nvd_no_key",
      level: "warn",
      message: "NVD feed without API key — rate limit is 5 req/30s. Register at nvd.nist.gov for a free key.",
      hint: "Set adapterConfig.apiKey to your NVD API key to avoid rate limiting.",
    });
  }

  return { adapterType: ctx.adapterType, status: summarize(checks), checks, testedAt: new Date().toISOString() };
}
