// SOC-on-LOC — AI-native Security Operations Orchestration
// Breaking Circuits LLC — breakingcircuits.com
// Forked from paperclipai/paperclip

export const COMPANY_STATUSES = ["active", "paused", "archived"] as const;
export type CompanyStatus = (typeof COMPANY_STATUSES)[number];

export const DEPLOYMENT_MODES = ["local_trusted", "authenticated"] as const;
export type DeploymentMode = (typeof DEPLOYMENT_MODES)[number];

export const DEPLOYMENT_EXPOSURES = ["private", "public"] as const;
export type DeploymentExposure = (typeof DEPLOYMENT_EXPOSURES)[number];

export const AUTH_BASE_URL_MODES = ["auto", "explicit"] as const;
export type AuthBaseUrlMode = (typeof AUTH_BASE_URL_MODES)[number];

export const AGENT_STATUSES = [
  "active",
  "paused",
  "idle",
  "running",
  "error",
  "pending_approval",
  "terminated",
] as const;
export type AgentStatus = (typeof AGENT_STATUSES)[number];

export const AGENT_ADAPTER_TYPES = [
  "process",
  "http",
  "claude_local",
  "codex_local",
  "opencode_local",
  "cursor",
  "openclaw",
  "siem",
  "threat_feed",
  "scanner",
  "edr",
] as const;
export type AgentAdapterType = (typeof AGENT_ADAPTER_TYPES)[number];

// --- Defender Roles (SOC-on-LOC) ---
export const AGENT_ROLES = [
  // Command
  "ciso",                 // Chief Information Security Officer
  "incident_commander",   // Leads active incident response

  // Offensive Security
  "red_teamer",           // Adversarial simulation, penetration testing
  "vulnerability_analyst",// CVE triage, CVSS scoring, patch prioritization

  // Defensive Security
  "blue_teamer",          // Active defense, rule tuning, SIEM management
  "threat_hunter",        // Proactive hunting for hidden threats
  "soc_analyst",          // Tier 1/2/3 alert triage and investigation
  "network_defender",     // NSM, firewall, IDS/IPS management
  "endpoint_defender",    // EDR, host-based detection and response

  // Intelligence
  "intel_analyst",        // Threat intelligence, IOC tracking, OSINT
  "malware_analyst",      // Reverse engineering, sandbox analysis

  // Forensics & Compliance
  "forensics_analyst",    // Digital forensics, evidence collection
  "compliance_officer",   // NIST/ISO 27001/FISMA/CIS framework mapping

  "general",
] as const;
export type AgentRole = (typeof AGENT_ROLES)[number];

export const AGENT_ICON_NAMES = [
  "bot",
  "cpu",
  "brain",
  "zap",
  "rocket",
  "code",
  "terminal",
  "shield",
  "eye",
  "search",
  "wrench",
  "hammer",
  "lightbulb",
  "sparkles",
  "star",
  "heart",
  "flame",
  "bug",
  "cog",
  "database",
  "globe",
  "lock",
  "mail",
  "message-square",
  "file-code",
  "git-branch",
  "package",
  "puzzle",
  "target",
  "wand",
  "atom",
  "circuit-board",
  "radar",
  "swords",
  "telescope",
  "microscope",
  "crown",
  "gem",
  "hexagon",
  "pentagon",
  "fingerprint",
  // SOC-on-LOC additions
  "wifi",
  "server",
  "alert-triangle",
  "activity",
  "crosshair",
  "key",
  "network",
] as const;
export type AgentIconName = (typeof AGENT_ICON_NAMES)[number];

// --- Incident Lifecycle Statuses (SOC-on-LOC) ---
export const ISSUE_STATUSES = [
  "new",            // Alert received, not yet triaged
  "triaging",       // Analyst reviewing — is this real?
  "confirmed",      // Confirmed incident, investigation begins
  "investigating",  // Active investigation underway
  "containing",     // Containment actions in progress
  "remediating",    // Root cause being fixed
  "resolved",       // Incident fully resolved and verified
  "closed",         // Archived
  "false_positive", // Confirmed false positive — no incident
  "accepted_risk",  // Real risk, security director accepted, no action taken
] as const;
export type IssueStatus = (typeof ISSUE_STATUSES)[number];

// --- Incident Severity (CVSS-aligned) ---
export const ISSUE_PRIORITIES = [
  "critical", // P0 — active breach, ransomware, data exfil in progress (CVSS 9.0-10.0)
  "high",     // P1 — confirmed threat, response required immediately (CVSS 7.0-8.9)
  "medium",   // P2 — suspicious activity, investigation needed (CVSS 4.0-6.9)
  "low",      // P3 — low-confidence signal (CVSS 0.1-3.9)
  "info",     // Telemetry / audit only — no immediate risk
] as const;
export type IssuePriority = (typeof ISSUE_PRIORITIES)[number];

// --- Mission Objective Hierarchy ---
export const GOAL_LEVELS = ["company", "team", "agent", "task"] as const;
export type GoalLevel = (typeof GOAL_LEVELS)[number];

export const GOAL_STATUSES = ["planned", "active", "achieved", "cancelled"] as const;
export type GoalStatus = (typeof GOAL_STATUSES)[number];

// --- Operation / Campaign Statuses ---
export const PROJECT_STATUSES = [
  "backlog",
  "planned",
  "in_progress",
  "completed",
  "cancelled",
] as const;
export type ProjectStatus = (typeof PROJECT_STATUSES)[number];

export const PROJECT_COLORS = [
  "#6366f1", // indigo
  "#8b5cf6", // violet
  "#ec4899", // pink
  "#ef4444", // red
  "#f97316", // orange
  "#eab308", // yellow
  "#22c55e", // green
  "#14b8a6", // teal
  "#06b6d4", // cyan
  "#3b82f6", // blue
] as const;

// --- Approval Gates ---
export const APPROVAL_TYPES = [
  "hire_agent",              // New defender hire — board approval required
  "approve_ceo_strategy",    // CISO strategic plan — board approval required
  "deploy_countermeasure",   // Automated response action — board approval required
  "accept_risk",             // Formal risk acceptance — board sign-off
] as const;
export type ApprovalType = (typeof APPROVAL_TYPES)[number];

export const APPROVAL_STATUSES = [
  "pending",
  "revision_requested",
  "approved",
  "rejected",
  "cancelled",
] as const;
export type ApprovalStatus = (typeof APPROVAL_STATUSES)[number];

// --- Infrastructure ---
export const SECRET_PROVIDERS = [
  "local_encrypted",
  "aws_secrets_manager",
  "gcp_secret_manager",
  "vault",
] as const;
export type SecretProvider = (typeof SECRET_PROVIDERS)[number];

export const STORAGE_PROVIDERS = ["local_disk", "s3"] as const;
export type StorageProvider = (typeof STORAGE_PROVIDERS)[number];

// --- Watch Cycle (Heartbeat) ---
export const HEARTBEAT_INVOCATION_SOURCES = [
  "timer",
  "assignment",
  "on_demand",
  "automation",
] as const;
export type HeartbeatInvocationSource = (typeof HEARTBEAT_INVOCATION_SOURCES)[number];

export const WAKEUP_TRIGGER_DETAILS = ["manual", "ping", "callback", "system"] as const;
export type WakeupTriggerDetail = (typeof WAKEUP_TRIGGER_DETAILS)[number];

export const WAKEUP_REQUEST_STATUSES = [
  "queued",
  "deferred_issue_execution",
  "claimed",
  "coalesced",
  "skipped",
  "completed",
  "failed",
  "cancelled",
] as const;
export type WakeupRequestStatus = (typeof WAKEUP_REQUEST_STATUSES)[number];

export const HEARTBEAT_RUN_STATUSES = [
  "queued",
  "running",
  "succeeded",
  "failed",
  "cancelled",
  "timed_out",
] as const;
export type HeartbeatRunStatus = (typeof HEARTBEAT_RUN_STATUSES)[number];

export const LIVE_EVENT_TYPES = [
  "heartbeat.run.queued",
  "heartbeat.run.status",
  "heartbeat.run.event",
  "heartbeat.run.log",
  "agent.status",
  "activity.logged",
] as const;
export type LiveEventType = (typeof LIVE_EVENT_TYPES)[number];

export const PRINCIPAL_TYPES = ["user", "agent"] as const;
export type PrincipalType = (typeof PRINCIPAL_TYPES)[number];

export const MEMBERSHIP_STATUSES = ["pending", "active", "suspended"] as const;
export type MembershipStatus = (typeof MEMBERSHIP_STATUSES)[number];

export const INSTANCE_USER_ROLES = ["instance_admin"] as const;
export type InstanceUserRole = (typeof INSTANCE_USER_ROLES)[number];

export const INVITE_TYPES = ["company_join", "bootstrap_ceo"] as const;
export type InviteType = (typeof INVITE_TYPES)[number];

export const INVITE_JOIN_TYPES = ["human", "agent", "both"] as const;
export type InviteJoinType = (typeof INVITE_JOIN_TYPES)[number];

export const JOIN_REQUEST_TYPES = ["human", "agent"] as const;
export type JoinRequestType = (typeof JOIN_REQUEST_TYPES)[number];

export const JOIN_REQUEST_STATUSES = ["pending_approval", "approved", "rejected"] as const;
export type JoinRequestStatus = (typeof JOIN_REQUEST_STATUSES)[number];

export const PERMISSION_KEYS = [
  "agents:create",
  "users:invite",
  "users:manage_permissions",
  "tasks:assign",
  "tasks:assign_scope",
  "joins:approve",
] as const;
export type PermissionKey = (typeof PERMISSION_KEYS)[number];

// =============================================================================
// SOC-on-LOC CYBER DEFENSE DOMAIN CONSTANTS
// Breaking Circuits LLC — breakingcircuits.com
// =============================================================================

// --- Kill Chain Stages (Lockheed Martin Cyber Kill Chain) ---
export const KILL_CHAIN_STAGES = [
  "reconnaissance",   // Target research, OSINT
  "weaponization",    // Malware crafting, exploit development
  "delivery",         // Phishing, drive-by, removable media
  "exploitation",     // Code execution, vulnerability triggered
  "installation",     // Backdoor, persistence mechanism installed
  "c2",               // Command & control channel established
  "exfiltration",     // Data exfil, lateral movement, objectives executed
] as const;
export type KillChainStage = (typeof KILL_CHAIN_STAGES)[number];

// --- MITRE ATT&CK Tactics (TA codes) ---
export const MITRE_TACTICS = [
  "TA0001", // Initial Access
  "TA0002", // Execution
  "TA0003", // Persistence
  "TA0004", // Privilege Escalation
  "TA0005", // Defense Evasion
  "TA0006", // Credential Access
  "TA0007", // Discovery
  "TA0008", // Lateral Movement
  "TA0009", // Collection
  "TA0010", // Exfiltration
  "TA0011", // Command and Control
  "TA0040", // Impact
  "TA0042", // Resource Development
  "TA0043", // Reconnaissance
] as const;
export type MitreTactic = (typeof MITRE_TACTICS)[number];

// --- Finding / Incident Types ---
export const FINDING_TYPES = [
  "alert",              // SIEM-generated alert
  "vulnerability",      // CVE / scanner finding
  "threat_hunt",        // Proactively discovered by threat hunter
  "red_team",           // Red team exercise finding
  "compliance",         // Compliance gap / policy violation
  "intel",              // Threat intelligence indicator
  "anomaly",            // Behavioral anomaly / ML detection
  "manual",             // Manually created by analyst
] as const;
export type FindingType = (typeof FINDING_TYPES)[number];

// --- Indicator of Compromise Types ---
export const IOC_TYPES = [
  "ip",           // IP address
  "cidr",         // IP range / subnet
  "domain",       // Domain name
  "url",          // Full URL
  "hash_md5",     // MD5 file hash
  "hash_sha1",    // SHA-1 file hash
  "hash_sha256",  // SHA-256 file hash
  "email",        // Email address
  "file_path",    // File system path
  "registry_key", // Windows registry key
  "user_agent",   // HTTP user agent string
  "certificate",  // TLS certificate fingerprint
  "mutex",        // Mutex / named pipe
] as const;
export type IocType = (typeof IOC_TYPES)[number];

// --- Asset Types ---
export const ASSET_TYPES = [
  "server",       // On-prem or cloud server
  "workstation",  // Desktop / laptop endpoint
  "network",      // Router, switch, firewall
  "cloud",        // Cloud resource (VM, container, function)
  "iot",          // IoT / OT device
  "mobile",       // Mobile device
  "saas",         // SaaS application
  "database",     // Database server
  "unknown",      // Unclassified
] as const;
export type AssetType = (typeof ASSET_TYPES)[number];

// --- Asset Criticality ---
export const ASSET_CRITICALITY = [
  "crown_jewel",  // Mission-critical; breach = catastrophic
  "critical",     // High business impact
  "high",         // Significant impact if compromised
  "medium",       // Moderate impact
  "low",          // Minimal impact
] as const;
export type AssetCriticality = (typeof ASSET_CRITICALITY)[number];

// --- Threat Feed Source Types ---
export const THREAT_FEED_TYPES = [
  "nvd",          // NIST National Vulnerability Database (CVE)
  "misp",         // MISP threat intelligence platform
  "otx",          // AlienVault Open Threat Exchange
  "stix_taxii",   // STIX/TAXII standard feed
  "vt",           // VirusTotal
  "shodan",       // Shodan internet scanner
  "custom",       // Custom HTTP feed
] as const;
export type ThreatFeedType = (typeof THREAT_FEED_TYPES)[number];

// --- IOC Confidence Levels ---
export const IOC_CONFIDENCE_LEVELS = [
  "confirmed",    // 90-100 — verified malicious
  "high",         // 70-89  — highly likely malicious
  "medium",       // 40-69  — suspicious
  "low",          // 10-39  — weak signal
  "unknown",      // 0      — unverified
] as const;
export type IocConfidenceLevel = (typeof IOC_CONFIDENCE_LEVELS)[number];

// --- Compliance Frameworks ---
export const COMPLIANCE_FRAMEWORKS = [
  "nist_csf",     // NIST Cybersecurity Framework
  "nist_800_53",  // NIST SP 800-53
  "iso_27001",    // ISO/IEC 27001
  "fisma",        // Federal Information Security Management Act
  "cis_v8",       // CIS Controls v8
  "soc2",         // SOC 2 Type II
  "pci_dss",      // PCI DSS
  "hipaa",        // HIPAA Security Rule
  "cmmc",         // CMMC (Defense contractors)
] as const;
export type ComplianceFramework = (typeof COMPLIANCE_FRAMEWORKS)[number];

// --- Containment Action Types ---
export const CONTAINMENT_ACTION_TYPES = [
  "block_ip",           // Firewall block rule added
  "block_domain",       // DNS sinkhole / firewall block
  "isolate_host",       // Network quarantine
  "disable_account",    // Account suspended
  "revoke_credentials", // API keys / tokens revoked
  "kill_process",       // Process terminated on endpoint
  "quarantine_file",    // File quarantined by EDR
  "patch_applied",      // Vulnerability patched
  "rule_added",         // Detection rule created
  "alert_suppressed",   // False positive suppressed
  "manual",             // Manual action taken
] as const;
export type ContainmentActionType = (typeof CONTAINMENT_ACTION_TYPES)[number];
