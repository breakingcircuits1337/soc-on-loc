import { useEffect, useMemo, useRef, useState } from "react";
import { Link } from "@/lib/router";
import { useQuery } from "@tanstack/react-query";
import { dashboardApi } from "../api/dashboard";
import { activityApi } from "../api/activity";
import { issuesApi } from "../api/issues";
import { agentsApi } from "../api/agents";
import { projectsApi } from "../api/projects";
import { heartbeatsApi } from "../api/heartbeats";
import { useCompany } from "../context/CompanyContext";
import { useDialog } from "../context/DialogContext";
import { useBreadcrumbs } from "../context/BreadcrumbContext";
import { queryKeys } from "../lib/queryKeys";
import { MetricCard } from "../components/MetricCard";
import { EmptyState } from "../components/EmptyState";
import { StatusIcon } from "../components/StatusIcon";
import { PriorityIcon } from "../components/PriorityIcon";
import { ActivityRow } from "../components/ActivityRow";
import { Identity } from "../components/Identity";
import { timeAgo } from "../lib/timeAgo";
import { cn, formatCents } from "../lib/utils";
import {
  ShieldAlert, Shield, Activity, Clock, AlertTriangle,
  LayoutDashboard, Crosshair, Radio, Cpu, Eye,
} from "lucide-react";
import { ActiveAgentsPanel } from "../components/ActiveAgentsPanel";
import { ChartCard, RunActivityChart, PriorityChart, IssueStatusChart, SuccessRateChart } from "../components/ActivityCharts";
import { PageSkeleton } from "../components/PageSkeleton";
import type { Agent, Issue } from "@paperclipai/shared";

/* ── Kill chain stage config ─────────────────────────────── */
const KILL_CHAIN_STAGES = [
  { key: "reconnaissance", label: "RECON", color: "#64748b" },
  { key: "weaponization",  label: "WEAPON", color: "#7c3aed" },
  { key: "delivery",       label: "DELIVERY", color: "#9333ea" },
  { key: "exploitation",   label: "EXPLOIT", color: "#dc2626" },
  { key: "installation",   label: "INSTALL", color: "#ea580c" },
  { key: "c2",             label: "C2", color: "#f97316" },
  { key: "exfiltration",   label: "EXFIL", color: "#ef4444" },
] as const;

/* ── Threat level calculation ─────────────────────────────── */
type ThreatLevel = "CRITICAL" | "HIGH" | "ELEVATED" | "GUARDED" | "NOMINAL";

function computeThreatLevel(issues: Issue[]): ThreatLevel {
  if (!issues.length) return "NOMINAL";
  const active = issues.filter(i =>
    !["resolved", "closed", "false_positive", "accepted_risk"].includes(i.status)
  );
  if (active.some(i => i.priority === "critical")) return "CRITICAL";
  if (active.some(i => i.priority === "high")) return "HIGH";
  if (active.some(i => i.priority === "medium")) return "ELEVATED";
  if (active.length > 0) return "GUARDED";
  return "NOMINAL";
}

const THREAT_CONFIG: Record<ThreatLevel, { label: string; border: string; text: string; bg: string; dot: string }> = {
  CRITICAL: {
    label: "CRITICAL — IMMEDIATE RESPONSE REQUIRED",
    border: "border-red-500/50",
    text: "text-red-400",
    bg: "bg-red-950/40",
    dot: "bg-red-400",
  },
  HIGH: {
    label: "HIGH — ELEVATED THREAT ACTIVITY DETECTED",
    border: "border-orange-500/40",
    text: "text-orange-400",
    bg: "bg-orange-950/30",
    dot: "bg-orange-400",
  },
  ELEVATED: {
    label: "ELEVATED — SUSPICIOUS ACTIVITY UNDER INVESTIGATION",
    border: "border-amber-500/40",
    text: "text-amber-400",
    bg: "bg-amber-950/25",
    dot: "bg-amber-400",
  },
  GUARDED: {
    label: "GUARDED — LOW CONFIDENCE SIGNALS DETECTED",
    border: "border-blue-500/30",
    text: "text-blue-400",
    bg: "bg-blue-950/20",
    dot: "bg-blue-400",
  },
  NOMINAL: {
    label: "NOMINAL — ALL SYSTEMS NOMINAL",
    border: "border-emerald-500/30",
    text: "text-emerald-400",
    bg: "bg-emerald-950/20",
    dot: "bg-emerald-400",
  },
};

/* ── Live UTC clock ───────────────────────────────────────── */
function useUtcClock() {
  const [time, setTime] = useState(() => new Date().toUTCString().slice(17, 25));
  useEffect(() => {
    const id = setInterval(() => setTime(new Date().toUTCString().slice(17, 25)), 1000);
    return () => clearInterval(id);
  }, []);
  return time;
}

/* ── Kill chain heatmap ───────────────────────────────────── */
function KillChainPanel({ issues }: { issues: Issue[] }) {
  const counts = useMemo(() => {
    const map: Record<string, number> = {};
    for (const s of KILL_CHAIN_STAGES) map[s.key] = 0;
    for (const issue of issues) {
      const stage = (issue as unknown as Record<string, unknown>)["killChainStage"] as string | undefined;
      if (stage && stage in map) map[stage]++;
    }
    return map;
  }, [issues]);

  const maxCount = Math.max(...Object.values(counts), 1);
  const totalMapped = Object.values(counts).reduce((a, b) => a + b, 0);

  return (
    <div className="border border-border dark:border-border/80 rounded-lg p-4 dark:bg-card/60">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground">
            Kill Chain Exposure
          </h3>
          <p className="text-[9px] text-muted-foreground/50 mt-0.5 font-mono">
            Lockheed Martin Cyber Kill Chain — active incident mapping
          </p>
        </div>
        <div className="flex items-center gap-1.5">
          <span className={cn(
            "h-1.5 w-1.5 rounded-full blink-dot",
            totalMapped > 0 ? "bg-red-400" : "bg-emerald-500"
          )} />
          <span className="text-[9px] font-mono text-muted-foreground/60 uppercase tracking-wider">
            {totalMapped > 0 ? `${totalMapped} mapped` : "clean"}
          </span>
        </div>
      </div>
      <div className="space-y-2">
        {KILL_CHAIN_STAGES.map((stage, idx) => {
          const count = counts[stage.key];
          const pct = Math.max((count / maxCount) * 100, count > 0 ? 4 : 0);
          return (
            <div key={stage.key} className="flex items-center gap-3">
              <span className="text-[9px] font-mono font-bold text-muted-foreground/60 w-14 shrink-0 text-right uppercase tracking-wider">
                {stage.label}
              </span>
              <div className="flex-1 h-3 bg-muted/20 rounded-sm overflow-hidden relative">
                {pct > 0 && (
                  <div
                    className="h-full rounded-sm kill-chain-bar"
                    style={{
                      width: `${pct}%`,
                      backgroundColor: stage.color,
                      animationDelay: `${idx * 60}ms`,
                      opacity: 0.85,
                    }}
                  />
                )}
                {pct === 0 && (
                  <div className="h-full w-full" style={{ background: "repeating-linear-gradient(90deg, transparent, transparent 6px, rgba(255,255,255,0.03) 6px, rgba(255,255,255,0.03) 7px)" }} />
                )}
              </div>
              <span className={cn(
                "text-[9px] font-mono tabular-nums w-4 text-right shrink-0",
                count > 0 ? "text-red-400 font-bold" : "text-muted-foreground/30"
              )}>
                {count > 0 ? count : "—"}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ── Threat status banner ─────────────────────────────────── */
function ThreatBanner({
  level, agentCount, activeAgents, utcTime
}: {
  level: ThreatLevel;
  agentCount: number;
  activeAgents: number;
  utcTime: string;
}) {
  const cfg = THREAT_CONFIG[level];
  return (
    <div className={cn(
      "rounded-lg border px-4 py-2.5 scan-shimmer relative overflow-hidden",
      cfg.bg, cfg.border,
    )}>
      <div className="flex items-center justify-between gap-4 flex-wrap relative z-10">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1.5">
            <span className={cn("h-2 w-2 rounded-full blink-dot shrink-0", cfg.dot)} />
            <span className={cn("text-[10px] font-mono font-bold uppercase tracking-widest", cfg.text)}>
              THREAT LEVEL: {level}
            </span>
          </div>
          <span className="text-[10px] text-muted-foreground/50 font-mono hidden sm:block">
            {cfg.label.split("—")[1]?.trim()}
          </span>
        </div>
        <div className="flex items-center gap-4 text-[9px] font-mono text-muted-foreground/60 uppercase tracking-wider">
          <span>
            <span className="text-cyan-400/80">{activeAgents}</span>/{agentCount} DEFENDERS
          </span>
          <span className="hidden sm:block">
            <span className="text-cyan-400/80">{utcTime}</span> UTC
          </span>
          <div className="flex items-center gap-1">
            <Radio className="h-2.5 w-2.5 text-cyan-400 blink-dot" />
            <span className="text-cyan-400/80">LIVE</span>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ── Main Dashboard ───────────────────────────────────────── */
function getRecentIssues(issues: Issue[]): Issue[] {
  return [...issues].sort((a, b) => new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime());
}

export function Dashboard() {
  const { selectedCompanyId, companies } = useCompany();
  const { openOnboarding } = useDialog();
  const { setBreadcrumbs } = useBreadcrumbs();
  const [animatedActivityIds, setAnimatedActivityIds] = useState<Set<string>>(new Set());
  const seenActivityIdsRef = useRef<Set<string>>(new Set());
  const hydratedActivityRef = useRef(false);
  const activityAnimationTimersRef = useRef<number[]>([]);
  const utcTime = useUtcClock();

  const { data: agents } = useQuery({
    queryKey: queryKeys.agents.list(selectedCompanyId!),
    queryFn: () => agentsApi.list(selectedCompanyId!),
    enabled: !!selectedCompanyId,
  });

  useEffect(() => {
    setBreadcrumbs([{ label: "SOC Dashboard" }]);
  }, [setBreadcrumbs]);

  const { data, isLoading, error } = useQuery({
    queryKey: queryKeys.dashboard(selectedCompanyId!),
    queryFn: () => dashboardApi.summary(selectedCompanyId!),
    enabled: !!selectedCompanyId,
  });

  const { data: activity } = useQuery({
    queryKey: queryKeys.activity(selectedCompanyId!),
    queryFn: () => activityApi.list(selectedCompanyId!),
    enabled: !!selectedCompanyId,
  });

  const { data: issues } = useQuery({
    queryKey: queryKeys.issues.list(selectedCompanyId!),
    queryFn: () => issuesApi.list(selectedCompanyId!),
    enabled: !!selectedCompanyId,
  });

  const { data: projects } = useQuery({
    queryKey: queryKeys.projects.list(selectedCompanyId!),
    queryFn: () => projectsApi.list(selectedCompanyId!),
    enabled: !!selectedCompanyId,
  });

  const { data: runs } = useQuery({
    queryKey: queryKeys.heartbeats(selectedCompanyId!),
    queryFn: () => heartbeatsApi.list(selectedCompanyId!),
    enabled: !!selectedCompanyId,
  });

  const recentIssues = issues ? getRecentIssues(issues) : [];
  const recentActivity = useMemo(() => (activity ?? []).slice(0, 12), [activity]);

  const threatLevel = useMemo(() => computeThreatLevel(issues ?? []), [issues]);

  /* Active incident counts */
  const activeIncidentCount = useMemo(() =>
    (issues ?? []).filter(i => !["resolved", "closed", "false_positive", "accepted_risk"].includes(i.status)).length,
    [issues]
  );
  const criticalIncidentCount = useMemo(() =>
    (issues ?? []).filter(i => i.priority === "critical" && !["resolved", "closed", "false_positive", "accepted_risk"].includes(i.status)).length,
    [issues]
  );

  const activeAgentCount = useMemo(() =>
    (agents ?? []).filter(a => ["active", "running"].includes(a.status)).length,
    [agents]
  );

  useEffect(() => {
    for (const timer of activityAnimationTimersRef.current) window.clearTimeout(timer);
    activityAnimationTimersRef.current = [];
    seenActivityIdsRef.current = new Set();
    hydratedActivityRef.current = false;
    setAnimatedActivityIds(new Set());
  }, [selectedCompanyId]);

  useEffect(() => {
    if (recentActivity.length === 0) return;
    const seen = seenActivityIdsRef.current;
    const currentIds = recentActivity.map((e) => e.id);
    if (!hydratedActivityRef.current) {
      for (const id of currentIds) seen.add(id);
      hydratedActivityRef.current = true;
      return;
    }
    const newIds = currentIds.filter((id) => !seen.has(id));
    if (newIds.length === 0) { for (const id of currentIds) seen.add(id); return; }
    setAnimatedActivityIds((prev) => { const next = new Set(prev); for (const id of newIds) next.add(id); return next; });
    for (const id of newIds) seen.add(id);
    const timer = window.setTimeout(() => {
      setAnimatedActivityIds((prev) => { const next = new Set(prev); for (const id of newIds) next.delete(id); return next; });
      activityAnimationTimersRef.current = activityAnimationTimersRef.current.filter((t) => t !== timer);
    }, 980);
    activityAnimationTimersRef.current.push(timer);
  }, [recentActivity]);

  useEffect(() => () => { for (const t of activityAnimationTimersRef.current) window.clearTimeout(t); }, []);

  const agentMap = useMemo(() => { const m = new Map<string, Agent>(); for (const a of agents ?? []) m.set(a.id, a); return m; }, [agents]);
  const entityNameMap = useMemo(() => {
    const m = new Map<string, string>();
    for (const i of issues ?? []) m.set(`issue:${i.id}`, i.identifier ?? i.id.slice(0, 8));
    for (const a of agents ?? []) m.set(`agent:${a.id}`, a.name);
    for (const p of projects ?? []) m.set(`project:${p.id}`, p.name);
    return m;
  }, [issues, agents, projects]);
  const entityTitleMap = useMemo(() => {
    const m = new Map<string, string>();
    for (const i of issues ?? []) m.set(`issue:${i.id}`, i.title);
    return m;
  }, [issues]);
  const agentName = (id: string | null) => id && agents ? (agents.find((a) => a.id === id)?.name ?? null) : null;

  if (!selectedCompanyId) {
    if (companies.length === 0) {
      return (
        <EmptyState
          icon={LayoutDashboard}
          message="Welcome to SOC-on-LOC. Set up your first SOC and deploy your first defender."
          action="Get Started"
          onAction={openOnboarding}
        />
      );
    }
    return <EmptyState icon={LayoutDashboard} message="Select or create a SOC to view the operations dashboard." />;
  }

  if (isLoading) return <PageSkeleton variant="dashboard" />;

  const hasNoAgents = agents !== undefined && agents.length === 0;

  return (
    <div className="space-y-4">
      {error && <p className="text-sm text-destructive">{error.message}</p>}

      {/* Threat Status Banner */}
      <ThreatBanner
        level={threatLevel}
        agentCount={agents?.length ?? 0}
        activeAgents={activeAgentCount}
        utcTime={utcTime}
      />

      {hasNoAgents && (
        <div className="flex items-center justify-between gap-3 rounded-lg border border-amber-500/30 bg-amber-950/30 px-4 py-3">
          <div className="flex items-center gap-2.5">
            <AlertTriangle className="h-4 w-4 text-amber-400 shrink-0" />
            <p className="text-sm text-amber-200/90 font-mono">
              No defenders deployed. Your SOC is unprotected.
            </p>
          </div>
          <button
            onClick={() => openOnboarding({ initialStep: 2, companyId: selectedCompanyId! })}
            className="text-xs font-bold text-amber-400 hover:text-amber-300 uppercase tracking-widest underline underline-offset-2 shrink-0 transition-colors"
          >
            Deploy Now
          </button>
        </div>
      )}

      <ActiveAgentsPanel companyId={selectedCompanyId!} />

      {data && (
        <>
          {/* Metric Cards */}
          <div className="grid grid-cols-2 xl:grid-cols-4 gap-2">
            <MetricCard
              icon={ShieldAlert}
              value={activeIncidentCount}
              label="Active Incidents"
              to="/issues"
              variant={criticalIncidentCount > 0 ? "critical" : activeIncidentCount > 0 ? "high" : "success"}
              description={
                <span>
                  {criticalIncidentCount} critical &bull; {data.tasks.inProgress} investigating
                </span>
              }
            />
            <MetricCard
              icon={Cpu}
              value={`${activeAgentCount}/${agents?.length ?? 0}`}
              label="Defenders Online"
              to="/agents"
              variant="cyber"
              description={
                <span>
                  {data.agents.running} on watch &bull; {data.agents.paused} standby &bull; {data.agents.error} error
                </span>
              }
            />
            <MetricCard
              icon={Activity}
              value={runs?.filter(r => {
                const d = new Date(r.createdAt);
                const now = new Date();
                return d.getFullYear() === now.getFullYear() && d.getMonth() === now.getMonth() && d.getDate() === now.getDate();
              }).length ?? 0}
              label="Watch Cycles Today"
              to="/costs"
              variant="intel"
              description={
                <span>
                  {formatCents(data.costs.monthSpendCents)} MTD &bull; {
                    data.costs.monthBudgetCents > 0
                      ? `${data.costs.monthUtilizationPercent}% of budget`
                      : "no cap"
                  }
                </span>
              }
            />
            <MetricCard
              icon={Eye}
              value={data.pendingApprovals}
              label="Pending Authorizations"
              to="/approvals"
              variant={data.pendingApprovals > 0 ? "high" : "default"}
              description={
                <span>
                  {data.staleTasks} stale &bull; {data.tasks.blocked} blocked
                </span>
              }
            />
          </div>

          {/* Kill Chain Heatmap */}
          <KillChainPanel issues={issues ?? []} />

          {/* Charts Row */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            <ChartCard title="Watch Cycle Activity" subtitle="Last 14 days">
              <RunActivityChart runs={runs ?? []} />
            </ChartCard>
            <ChartCard title="Incident Severity" subtitle="Last 14 days">
              <PriorityChart issues={issues ?? []} />
            </ChartCard>
            <ChartCard title="Incident Pipeline" subtitle="Last 14 days">
              <IssueStatusChart issues={issues ?? []} />
            </ChartCard>
            <ChartCard title="Defender Success Rate" subtitle="Last 14 days">
              <SuccessRateChart runs={runs ?? []} />
            </ChartCard>
          </div>

          {/* Bottom two-column: Intel Feed + Active Incidents */}
          <div className="grid md:grid-cols-2 gap-4">
            {/* Live Intel Feed */}
            {recentActivity.length > 0 && (
              <div className="min-w-0">
                <div className="flex items-center gap-2 mb-3">
                  <Radio className="h-3 w-3 text-cyan-400 blink-dot" />
                  <h3 className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest">
                    Live Intel Feed
                  </h3>
                </div>
                <div className="border border-border dark:border-border/70 divide-y divide-border overflow-hidden rounded-lg dark:bg-card/40">
                  {recentActivity.map((event) => (
                    <ActivityRow
                      key={event.id}
                      event={event}
                      agentMap={agentMap}
                      entityNameMap={entityNameMap}
                      entityTitleMap={entityTitleMap}
                      className={animatedActivityIds.has(event.id) ? "activity-row-enter" : undefined}
                    />
                  ))}
                </div>
              </div>
            )}

            {/* Active Incidents */}
            <div className="min-w-0">
              <div className="flex items-center gap-2 mb-3">
                <Crosshair className="h-3 w-3 text-red-400" />
                <h3 className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest">
                  Active Incidents
                </h3>
              </div>
              {recentIssues.length === 0 ? (
                <div className="border border-emerald-500/20 dark:bg-emerald-950/20 rounded-lg p-6 text-center">
                  <Shield className="h-6 w-6 text-emerald-400/60 mx-auto mb-2" />
                  <p className="text-xs text-emerald-400/70 font-mono uppercase tracking-widest">No active incidents</p>
                </div>
              ) : (
                <div className="border border-border dark:border-border/70 divide-y divide-border overflow-hidden rounded-lg dark:bg-card/40">
                  {recentIssues.slice(0, 10).map((issue) => (
                    <Link
                      key={issue.id}
                      to={`/issues/${issue.identifier ?? issue.id}`}
                      className="px-4 py-2.5 text-sm cursor-pointer hover:bg-accent/40 transition-colors no-underline text-inherit flex gap-3 items-center"
                    >
                      <div className="flex items-center gap-2 shrink-0">
                        <PriorityIcon priority={issue.priority} />
                        <StatusIcon status={issue.status} />
                      </div>
                      <p className="min-w-0 flex-1 truncate font-mono text-xs">
                        <span className="text-muted-foreground/50 mr-1.5">{issue.identifier ?? issue.id.slice(0, 6)}</span>
                        <span>{issue.title}</span>
                        {issue.assigneeAgentId && (() => {
                          const name = agentName(issue.assigneeAgentId);
                          return name ? <span className="hidden sm:inline"><Identity name={name} size="sm" className="ml-2 inline-flex" /></span> : null;
                        })()}
                      </p>
                      <span className="text-[9px] text-muted-foreground/40 shrink-0 font-mono tabular-nums">
                        {timeAgo(issue.updatedAt)}
                      </span>
                    </Link>
                  ))}
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
