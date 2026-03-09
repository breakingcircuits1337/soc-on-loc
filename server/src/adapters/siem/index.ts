// SOC-on-LOC — SIEM Adapter
// Polls a SIEM REST API (Splunk, Elastic, Sentinel, QRadar) for alerts on each watch cycle.
// Breaking Circuits LLC — breakingcircuits.com

import type { ServerAdapterModule } from "../types.js";
import { execute } from "./execute.js";
import { testEnvironment } from "./test.js";

export const siemAdapter: ServerAdapterModule = {
  type: "siem",
  execute,
  testEnvironment,
  models: [],
  agentConfigurationDoc: `# siem agent configuration

Adapter: siem

On each watch cycle this adapter polls your SIEM REST API for new alerts,
normalises the response, and returns a structured summary for the defender agent.

## Required fields
- url (string): SIEM REST API alerts endpoint
  - Splunk:   https://splunk:8089/services/search/jobs/export?search=...
  - Elastic:  https://elastic:9200/.siem-signals-*/_search
  - Sentinel: https://management.azure.com/subscriptions/.../alerts?api-version=...
  - QRadar:   https://qradar/api/siem/offenses

## Authentication
- apiKey (string): API key or bearer token
- authHeader (string, optional): header name — default "Authorization"
- authPrefix (string, optional): token prefix — default "Bearer"
- headers (object, optional): additional request headers

## Tuning
- limit (number, optional): max alerts to fetch per cycle — default 50
- limitParam (string, optional): query param name for limit — default "limit"
- timeoutMs (number, optional): request timeout in milliseconds — default 10000
- dryRun (boolean, optional): skip actual fetch, useful for testing config
`,
};
