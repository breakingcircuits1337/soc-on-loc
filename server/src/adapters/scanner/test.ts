// SOC-on-LOC — Scanner Adapter: Environment Test
// Breaking Circuits LLC — breakingcircuits.com

import type {
  AdapterEnvironmentCheck,
  AdapterEnvironmentTestContext,
  AdapterEnvironmentTestResult,
} from "../types.js";
import { asString, asStringArray, parseObject } from "../utils.js";
import { ensureCommandResolvable } from "../utils.js";

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

  const tool = asString(config.tool, "nmap");
  const targets = asStringArray(config.targets);
  const customCommand = asString(config.command, "");

  checks.push({ code: "scanner_tool", level: "info", message: `Scanner tool: ${tool}` });

  if (targets.length === 0) {
    checks.push({
      code: "scanner_targets_missing",
      level: "error",
      message: "targets array is required (e.g. [\"192.168.1.0/24\"])",
      hint: "Set adapterConfig.targets to a list of IPs, CIDRs, or hostnames.",
    });
  } else {
    checks.push({
      code: "scanner_targets_set",
      level: "info",
      message: `${targets.length} target(s): ${targets.slice(0, 3).join(", ")}${targets.length > 3 ? "..." : ""}`,
    });
  }

  const commandToCheck = tool === "custom" ? customCommand : tool === "nmap" ? "nmap" : "nuclei";

  if (tool === "custom" && !customCommand) {
    checks.push({
      code: "scanner_custom_command_missing",
      level: "error",
      message: "custom tool requires adapterConfig.command to be set.",
    });
  } else if (commandToCheck) {
    try {
      await ensureCommandResolvable(commandToCheck, "/tmp", process.env as NodeJS.ProcessEnv);
      checks.push({ code: "scanner_command_found", level: "info", message: `${commandToCheck} found on PATH.` });
    } catch {
      checks.push({
        code: "scanner_command_not_found",
        level: "error",
        message: `Command not found: ${commandToCheck}`,
        hint: tool === "nmap"
          ? "Install nmap: sudo apt install nmap"
          : tool === "nuclei"
          ? "Install nuclei: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
          : `Ensure '${commandToCheck}' is on PATH.`,
      });
    }
  }

  return { adapterType: ctx.adapterType, status: summarize(checks), checks, testedAt: new Date().toISOString() };
}
