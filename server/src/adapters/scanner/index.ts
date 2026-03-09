// SOC-on-LOC — Scanner Adapter
// Runs nmap / nuclei / custom scanners as subprocesses on each watch cycle.
// Breaking Circuits LLC — breakingcircuits.com

import type { ServerAdapterModule } from "../types.js";
import { execute } from "./execute.js";
import { testEnvironment } from "./test.js";

export const scannerAdapter: ServerAdapterModule = {
  type: "scanner",
  execute,
  testEnvironment,
  models: [],
  agentConfigurationDoc: `# scanner agent configuration

Adapter: scanner

On each watch cycle this adapter runs a network or vulnerability scanner
as a subprocess, parses the output, and returns a structured finding summary.
Assign this adapter to vulnerability_analyst or network_defender agents.

## Required fields
- tool (string): scanner to use — nmap | nuclei | custom
- targets (string[]): list of IPs, CIDRs, or hostnames to scan
  Example: ["192.168.1.0/24", "10.0.0.1"]

## Tool-specific config

### nmap
- flags (string[], optional): extra nmap flags
  Example: ["-sV", "-sC", "-p", "1-1000", "--script=vuln"]

### nuclei
- flags (string[], optional): extra nuclei flags
  Example: ["-t", "cves/", "-severity", "critical,high"]

### custom
- command (string, required): executable to run
- flags (string[], optional): flags passed before targets

## Shared options
- timeoutSec (number, optional): subprocess timeout in seconds — default 300
- dryRun (boolean, optional): log the intended command without executing

## Notes
- nmap requires installation: sudo apt install nmap
- nuclei requires installation: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
- Ensure the SOC-on-LOC server has network access to scan targets
- Scans run under the server process user — ensure appropriate permissions
`,
};
