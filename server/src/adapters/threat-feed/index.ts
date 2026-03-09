// SOC-on-LOC — Threat Feed Adapter
// Polls external threat intelligence sources on each watch cycle.
// Breaking Circuits LLC — breakingcircuits.com

import type { ServerAdapterModule } from "../types.js";
import { execute } from "./execute.js";
import { testEnvironment } from "./test.js";

export const threatFeedAdapter: ServerAdapterModule = {
  type: "threat_feed",
  execute,
  testEnvironment,
  models: [],
  agentConfigurationDoc: `# threat_feed agent configuration

Adapter: threat_feed

On each watch cycle this adapter polls an external threat intelligence source,
normalises the response into structured IOC / CVE items, and returns a summary.
Assign this adapter to intel_analyst defenders.

## Required fields
- feedType (string): one of nvd | otx | misp | stix_taxii | vt | shodan | custom

## Feed-specific config

### nvd (NIST National Vulnerability Database)
- apiKey (string, optional): NVD API key — register free at nvd.nist.gov
  Without a key you are rate-limited to 5 req/30s.

### otx (AlienVault Open Threat Exchange)
- apiKey (string, required): OTX API key from otx.alienvault.com

### misp (MISP Threat Intelligence Platform)
- url (string, required): MISP instance base URL (e.g. https://misp.internal)
- apiKey (string, required): MISP auth key

### stix_taxii | vt | shodan | custom (generic REST)
- url (string, required): feed endpoint URL
- apiKey (string, optional): bearer token
- headers (object, optional): additional request headers

## Shared options
- lookbackDays (number, optional): how many days back to query — default 1
- timeoutMs (number, optional): request timeout in milliseconds — default 15000
- dryRun (boolean, optional): skip fetch, useful for config validation
`,
};
