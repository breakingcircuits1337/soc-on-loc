// SOC-on-LOC — Scanner Adapter: Execute
// Runs network/vulnerability scanners (nmap, nuclei) as subprocesses on each watch cycle.
// Breaking Circuits LLC — breakingcircuits.com

import type { AdapterExecutionContext, AdapterExecutionResult } from "../types.js";
import { asString, asNumber, asBoolean, asStringArray, parseObject } from "../utils.js";
import { runChildProcess } from "../utils.js";

type ScannerTool = "nmap" | "nuclei" | "custom";

function buildNmapArgs(targets: string[], flags: string[], outputFile: string): string[] {
  return [
    ...targets,
    "-oX", outputFile,
    "--open",
    ...flags,
  ];
}

function buildNucleiArgs(targets: string[], flags: string[], outputFile: string): string[] {
  return [
    "-target", targets.join(","),
    "-json-export", outputFile,
    "-silent",
    ...flags,
  ];
}

function extractNmapSummary(stdout: string): { hostCount: number; openPortCount: number } {
  const hostMatch = stdout.match(/(\d+) host[s]? up/i);
  const portLines = (stdout.match(/open/gi) ?? []).length;
  return { hostCount: hostMatch ? parseInt(hostMatch[1], 10) : 0, openPortCount: portLines };
}

function extractNucleiSummary(stdout: string): { findingCount: number; criticalCount: number } {
  const lines = stdout.split("\n").filter(Boolean);
  let critical = 0;
  for (const line of lines) {
    try {
      const obj = JSON.parse(line) as { info?: { severity?: string } };
      if (/critical|high/i.test(obj.info?.severity ?? "")) critical++;
    } catch { /* skip non-JSON lines */ }
  }
  return { findingCount: lines.length, criticalCount: critical };
}

export async function execute(ctx: AdapterExecutionContext): Promise<AdapterExecutionResult> {
  const { config, runId } = ctx;

  const tool = asString(config.tool, "nmap") as ScannerTool;
  const rawTargets = asStringArray(config.targets);
  const targets = rawTargets.length > 0 ? rawTargets : [];
  const flags = asStringArray(config.flags);
  const extraEnv = parseObject(config.env) as Record<string, string>;
  const timeoutSec = asNumber(config.timeoutSec, 300);
  const dryRun = asBoolean(config.dryRun, false);

  if (targets.length === 0) throw new Error("Scanner adapter: targets array is required");

  if (dryRun) {
    return {
      exitCode: 0,
      signal: null,
      timedOut: false,
      summary: `Scanner dry-run (${tool}) against ${targets.join(", ")} — not executed`,
    };
  }

  const outputFile = `/tmp/sol-scan-${runId}.out`;
  let command: string;
  let args: string[];

  switch (tool) {
    case "nmap":
      command = "nmap";
      args = buildNmapArgs(targets, flags, outputFile);
      break;
    case "nuclei":
      command = "nuclei";
      args = buildNucleiArgs(targets, flags, outputFile);
      break;
    case "custom":
    default: {
      command = asString(config.command, "");
      if (!command) throw new Error("Scanner adapter: command is required for custom tool");
      args = [...flags, ...targets];
      break;
    }
  }

  let stdout = "";
  let stderr = "";

  const result = await runChildProcess(runId, command, args, {
    cwd: "/tmp",
    env: { ...extraEnv },
    timeoutSec,
    graceSec: 10,
    onLog: async (stream, chunk) => {
      if (stream === "stdout") stdout += chunk;
      else stderr += chunk;
    },
  });

  let summary: string;
  let resultData: Record<string, unknown> = { tool, targets, exitCode: result.exitCode };

  if (tool === "nmap") {
    const { hostCount, openPortCount } = extractNmapSummary(stdout);
    summary = `nmap: ${hostCount} host(s) up, ${openPortCount} open port(s) across ${targets.join(", ")}`;
    resultData = { ...resultData, hostCount, openPortCount };
  } else if (tool === "nuclei") {
    const { findingCount, criticalCount } = extractNucleiSummary(stdout);
    summary = `nuclei: ${findingCount} finding(s) — ${criticalCount} critical/high across ${targets.join(", ")}`;
    resultData = { ...resultData, findingCount, criticalCount };
  } else {
    summary = `Scanner (${command}) exited ${result.exitCode} against ${targets.join(", ")}`;
  }

  if (result.timedOut) summary = `[TIMED OUT] ${summary}`;

  return {
    exitCode: result.exitCode,
    signal: result.signal,
    timedOut: result.timedOut,
    summary,
    resultJson: { ...resultData, stderrSnippet: stderr.slice(0, 500) },
  };
}
