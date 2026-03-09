// SOC-on-LOC — SIEM Adapter: Environment Test
// Breaking Circuits LLC — breakingcircuits.com

import type {
  AdapterEnvironmentCheck,
  AdapterEnvironmentTestContext,
  AdapterEnvironmentTestResult,
} from "../types.js";
import { asString, asNumber, parseObject } from "../utils.js";

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

  const urlValue = asString(config.url, "");
  const apiKey = asString(config.apiKey, "");
  const timeoutMs = asNumber(config.timeoutMs, 10000);

  if (!urlValue) {
    checks.push({
      code: "siem_url_missing",
      level: "error",
      message: "SIEM adapter requires a url.",
      hint: "Set adapterConfig.url to your SIEM REST API alerts endpoint.",
    });
    return { adapterType: ctx.adapterType, status: summarize(checks), checks, testedAt: new Date().toISOString() };
  }

  let url: URL | null = null;
  try {
    url = new URL(urlValue);
  } catch {
    checks.push({ code: "siem_url_invalid", level: "error", message: `Invalid URL: ${urlValue}` });
  }

  if (url) {
    checks.push({ code: "siem_url_valid", level: "info", message: `SIEM endpoint: ${url.toString()}` });
  }

  if (!apiKey) {
    checks.push({
      code: "siem_apikey_missing",
      level: "warn",
      message: "No apiKey configured — requests will be unauthenticated.",
      hint: "Set adapterConfig.apiKey if your SIEM requires authentication.",
    });
  } else {
    checks.push({ code: "siem_apikey_present", level: "info", message: "API key configured." });
  }

  if (url) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), Math.min(timeoutMs, 5000));
    try {
      const res = await fetch(url.toString(), { method: "HEAD", signal: controller.signal });
      if (res.ok || res.status === 405) {
        checks.push({ code: "siem_endpoint_reachable", level: "info", message: `Endpoint reachable (HTTP ${res.status}).` });
      } else {
        checks.push({
          code: "siem_endpoint_unexpected_status",
          level: "warn",
          message: `Endpoint probe returned HTTP ${res.status}.`,
          hint: "Verify the SIEM API URL and credentials.",
        });
      }
    } catch (err) {
      checks.push({
        code: "siem_endpoint_unreachable",
        level: "warn",
        message: err instanceof Error ? err.message : "Endpoint probe failed",
        hint: "Ensure the SIEM API is reachable from this host.",
      });
    } finally {
      clearTimeout(timer);
    }
  }

  return { adapterType: ctx.adapterType, status: summarize(checks), checks, testedAt: new Date().toISOString() };
}
