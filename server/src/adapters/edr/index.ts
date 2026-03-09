// SOC-on-LOC — EDR Adapter
// Polls an EDR platform for recent detections on each watch cycle.
// Breaking Circuits LLC — breakingcircuits.com

import type { ServerAdapterModule } from "../types.js";
import { execute } from "./execute.js";
import { testEnvironment } from "./test.js";

export const edrAdapter: ServerAdapterModule = {
  type: "edr",
  execute,
  testEnvironment,
  models: [],
  agentConfigurationDoc: `# edr agent configuration

Adapter: edr

On each watch cycle this adapter polls your EDR platform's REST API for recent detections,
normalises the response, and returns a structured summary for the endpoint_defender agent.

## Required fields
- platform (string): one of crowdstrike | sentinelone | defender | carbonblack | custom

## Platform-specific config

### crowdstrike
- clientId (string, required): Falcon API OAuth2 client ID
- clientSecret (string, required): Falcon API OAuth2 client secret
- cloud (string, optional): cloud region — us-1 | us-2 | eu-1 — default us-1

### sentinelone
- url (string, required): SentinelOne management console URL
- apiKey (string, required): SentinelOne API token

### defender (Microsoft Defender for Endpoint)
- url (string, required): MDE API endpoint
- apiKey (string, required): Azure AD bearer token
- headers (object, optional): additional headers

### carbonblack | custom (generic REST)
- url (string, required): alerts/detections REST endpoint
- apiKey (string, optional): bearer token
- headers (object, optional): additional request headers

## Shared options
- limit (number, optional): max detections to fetch per cycle — default 50
- timeoutMs (number, optional): request timeout in milliseconds — default 15000
- dryRun (boolean, optional): skip fetch for config validation
`,
};
