import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/lib/auth";
import {
  Play, Square, Scan, RefreshCw, Shield, AlertTriangle, Activity,
  Clock, CheckCircle, XCircle, Zap, Eye, Bug, TrendingUp, Server,
  FileWarning, Lock, Cpu,
} from "lucide-react";

interface EngineStatus {
  state: string;
  threatLevel: string;
  uptimeMs: number;
  tasksDone: number;
  tasksFailed: number;
  activeTask: string | null;
  lastScan: number | null;
  lastIntel: number | null;
  lastHuntResult: {
    findings: number;
    critical: number;
    high: number;
    modules: string[];
    durationMs: number;
  } | null;
  lastIntelResult: {
    newRules: number;
    newBlocked: number;
    totalPatterns: number;
    durationMs: number;
  } | null;
  threatPatterns: number;
  recentTasks: Array<{
    id: string;
    name: string;
    status: string;
    completedAt?: number;
    error?: string;
  }>;
}

interface Finding {
  id: string;
  hunt: string;
  severity: string;
  title: string;
  description: string;
  evidence: Record<string, any>;
  remediation: string;
  cmmc: string[];
}

interface ThreatPattern {
  id: string;
  source: string;
  severity: string;
  title: string;
  cveId: string;
  policyRule: { name: string; action: string; severity: string; category: string };
  cmmc: string[];
}

const severityColors: Record<string, string> = {
  critical: "bg-red-500/10 text-red-500 border-red-500/20",
  high: "bg-orange-500/10 text-orange-500 border-orange-500/20",
  medium: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
  low: "bg-blue-500/10 text-blue-500 border-blue-500/20",
};

const threatLevelColors: Record<string, string> = {
  nominal: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
  elevated: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
  critical: "bg-red-500/10 text-red-400 border-red-500/30",
};

const stateColors: Record<string, string> = {
  running: "bg-emerald-500/10 text-emerald-400",
  shutdown: "bg-gray-500/10 text-gray-400",
  initializing: "bg-blue-500/10 text-blue-400",
  suspended: "bg-yellow-500/10 text-yellow-400",
};

const huntModuleIcons: Record<string, typeof Bug> = {
  cred_scan: Lock,
  injection: Bug,
  behavior: TrendingUp,
  policy_trend: FileWarning,
  server_exposure: Server,
};

const huntModuleLabels: Record<string, string> = {
  cred_scan: "Credential Scan",
  injection: "Injection Hunt",
  behavior: "Behavioral Analysis",
  policy_trend: "Policy Trend",
  server_exposure: "Server Exposure",
};

const sourceLabels: Record<string, string> = {
  internal: "Internal Research",
  nvd: "NVD / CVE Database",
  owasp: "OWASP Agentic Top 10",
};

const sourceColors: Record<string, string> = {
  internal: "bg-purple-500/10 text-purple-400 border-purple-500/20",
  nvd: "bg-red-500/10 text-red-400 border-red-500/20",
  owasp: "bg-orange-500/10 text-orange-400 border-orange-500/20",
};

function formatUptime(ms: number): string {
  const s = Math.floor(ms / 1000);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s % 60}s`;
  return `${s}s`;
}

function formatAgo(ts: number | null): string {
  if (!ts) return "Never";
  const ago = Date.now() - ts;
  if (ago < 60000) return "Just now";
  if (ago < 3600000) return `${Math.floor(ago / 60000)}m ago`;
  return `${Math.floor(ago / 3600000)}h ago`;
}

export default function EnginePage() {
  const { toast } = useToast();
  const { isAdmin, isAnalyst } = useAuth();
  const canOperate = isAdmin || isAnalyst;

  const { data: status, isLoading: statusLoading } = useQuery<EngineStatus>({
    queryKey: ["/api/engine/status"],
    refetchInterval: 5000,
  });

  const { data: findings = [] } = useQuery<Finding[]>({
    queryKey: ["/api/engine/findings"],
    refetchInterval: 10000,
  });

  const { data: patterns = [] } = useQuery<ThreatPattern[]>({
    queryKey: ["/api/engine/patterns"],
  });

  const startMutation = useMutation({
    mutationFn: () => apiRequest("POST", "/api/engine/start"),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/engine/status"] });
      toast({ title: "Engine started", description: "Autonomous threat scanner is now active." });
    },
    onError: (e: Error) => toast({ title: "Failed to start engine", description: e.message, variant: "destructive" }),
  });

  const stopMutation = useMutation({
    mutationFn: () => apiRequest("POST", "/api/engine/stop"),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/engine/status"] });
      toast({ title: "Engine stopped" });
    },
    onError: (e: Error) => toast({ title: "Failed to stop", description: e.message, variant: "destructive" }),
  });

  const scanMutation = useMutation({
    mutationFn: () => apiRequest("POST", "/api/engine/scan"),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/engine/status"] });
      queryClient.invalidateQueries({ queryKey: ["/api/engine/findings"] });
      toast({ title: "Scan complete", description: "Threat hunt finished." });
    },
    onError: (e: Error) => toast({ title: "Scan failed", description: e.message, variant: "destructive" }),
  });

  const intelMutation = useMutation({
    mutationFn: () => apiRequest("POST", "/api/engine/intel"),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/engine/status"] });
      toast({ title: "Intel refreshed", description: "Threat intelligence updated." });
    },
    onError: (e: Error) => toast({ title: "Intel refresh failed", description: e.message, variant: "destructive" }),
  });

  const isRunning = status?.state === "running";

  return (
    <div className="p-6 space-y-6 max-w-[1400px] mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight" data-testid="heading-engine">Command Center</h1>
        </div>
        {canOperate && (
          <div className="flex items-center gap-2" data-testid="engine-controls">
            {isRunning ? (
              <Button
                variant="destructive"
                size="sm"
                onClick={() => stopMutation.mutate()}
                disabled={stopMutation.isPending}
                data-testid="button-engine-stop"
              >
                <Square className="w-4 h-4 mr-1" />
                Stop Engine
              </Button>
            ) : (
              <Button
                size="sm"
                onClick={() => startMutation.mutate()}
                disabled={startMutation.isPending}
                data-testid="button-engine-start"
              >
                <Play className="w-4 h-4 mr-1" />
                Start Engine
              </Button>
            )}
            <Button
              variant="outline"
              size="sm"
              onClick={() => scanMutation.mutate()}
              disabled={scanMutation.isPending}
              data-testid="button-engine-scan"
            >
              <Scan className="w-4 h-4 mr-1" />
              {scanMutation.isPending ? "Scanning..." : "Run Scan"}
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => intelMutation.mutate()}
              disabled={intelMutation.isPending}
              data-testid="button-engine-intel"
            >
              <RefreshCw className="w-4 h-4 mr-1" />
              {intelMutation.isPending ? "Refreshing..." : "Refresh Intel"}
            </Button>
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card data-testid="card-engine-state">
          <CardContent className="p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-muted-foreground uppercase tracking-wider">Engine State</span>
              <Cpu className="w-4 h-4 text-muted-foreground" />
            </div>
            <div className="flex items-center gap-2">
              <Badge variant="outline" className={stateColors[status?.state || "shutdown"]}>
                {(status?.state || "shutdown").toUpperCase()}
              </Badge>
              {isRunning && status?.activeTask && (
                <span className="text-xs text-muted-foreground animate-pulse">{status.activeTask}</span>
              )}
            </div>
            {isRunning && (
              <p className="text-xs text-muted-foreground mt-2">
                Uptime: {formatUptime(status?.uptimeMs || 0)}
              </p>
            )}
          </CardContent>
        </Card>

        <Card data-testid="card-threat-level">
          <CardContent className="p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-muted-foreground uppercase tracking-wider">Threat Level</span>
              <Shield className="w-4 h-4 text-muted-foreground" />
            </div>
            <Badge
              variant="outline"
              className={`text-base px-3 py-1 ${threatLevelColors[status?.threatLevel || "nominal"]}`}
            >
              {(status?.threatLevel || "NOMINAL").toUpperCase()}
            </Badge>
          </CardContent>
        </Card>

        <Card data-testid="card-tasks-summary">
          <CardContent className="p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-muted-foreground uppercase tracking-wider">Tasks</span>
              <Activity className="w-4 h-4 text-muted-foreground" />
            </div>
            <div className="flex items-center gap-4">
              <div>
                <p className="text-xl font-bold">{status?.tasksDone || 0}</p>
                <p className="text-xs text-muted-foreground">Completed</p>
              </div>
              <div>
                <p className="text-xl font-bold text-red-400">{status?.tasksFailed || 0}</p>
                <p className="text-xs text-muted-foreground">Failed</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card data-testid="card-schedule">
          <CardContent className="p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-muted-foreground uppercase tracking-wider">Schedule</span>
              <Clock className="w-4 h-4 text-muted-foreground" />
            </div>
            <div className="space-y-1 text-xs">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Last scan</span>
                <span>{formatAgo(status?.lastScan || null)}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Last intel</span>
                <span>{formatAgo(status?.lastIntel || null)}</span>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {status?.lastHuntResult && (
        <Card data-testid="card-last-hunt">
          <CardHeader className="pb-3">
            <CardTitle className="text-base flex items-center gap-2">
              <Scan className="w-4 h-4 text-primary" />
              Last Hunt Result
            </CardTitle>
            <CardDescription>
              {status.lastHuntResult.findings} findings ({status.lastHuntResult.critical} critical, {status.lastHuntResult.high} high) in {status.lastHuntResult.durationMs}ms
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              {status.lastHuntResult.modules.map((mod) => {
                const Icon = huntModuleIcons[mod] || Eye;
                return (
                  <Badge key={mod} variant="outline" className="gap-1" data-testid={`badge-module-${mod}`}>
                    <Icon className="w-3 h-3" />
                    {huntModuleLabels[mod] || mod}
                  </Badge>
                );
              })}
            </div>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card data-testid="card-findings">
          <CardHeader className="pb-3">
            <CardTitle className="text-base flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-primary" />
              Active Findings
              {findings.length > 0 && (
                <Badge variant="outline" className="ml-auto">{findings.length}</Badge>
              )}
            </CardTitle>
            <CardDescription>
              Threat hunt findings from the latest scan cycle
            </CardDescription>
          </CardHeader>
          <CardContent>
            {findings.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground" data-testid="text-no-findings">
                <Shield className="w-8 h-8 mx-auto mb-2 opacity-30" />
                <p className="text-sm">No findings. Run a scan to start hunting.</p>
              </div>
            ) : (
              <div className="space-y-3 max-h-[500px] overflow-y-auto">
                {findings.map((f, i) => (
                  <div
                    key={f.id}
                    className="p-3 rounded-lg border bg-card hover:bg-accent/5 transition-colors"
                    data-testid={`finding-${i}`}
                  >
                    <div className="flex items-start justify-between gap-2 mb-1">
                      <h4 className="text-sm font-medium leading-snug">{f.title}</h4>
                      <Badge variant="outline" className={`shrink-0 ${severityColors[f.severity]}`}>
                        {f.severity}
                      </Badge>
                    </div>
                    <p className="text-xs text-muted-foreground mb-2">{f.description}</p>
                    <div className="flex items-center gap-2 flex-wrap">
                      <Badge variant="secondary" className="text-[10px]">
                        {huntModuleLabels[f.hunt] || f.hunt}
                      </Badge>
                      {f.cmmc.map(c => (
                        <Badge key={c} variant="outline" className="text-[10px]">{c}</Badge>
                      ))}
                    </div>
                    {f.remediation && (
                      <p className="text-xs text-primary/80 mt-2 flex items-start gap-1">
                        <Zap className="w-3 h-3 mt-0.5 shrink-0" />
                        {f.remediation}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        <Card data-testid="card-threat-intel">
          <CardHeader className="pb-3">
            <CardTitle className="text-base flex items-center gap-2">
              <Eye className="w-4 h-4 text-primary" />
              Threat Intelligence
              <Badge variant="outline" className="ml-auto">{patterns.length} patterns</Badge>
            </CardTitle>
            <CardDescription>
              Built-in threat patterns from NVD, OWASP, and internal research
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3 max-h-[500px] overflow-y-auto">
              {patterns.map((tp) => (
                <div
                  key={tp.id}
                  className="p-3 rounded-lg border bg-card hover:bg-accent/5 transition-colors"
                  data-testid={`pattern-${tp.id}`}
                >
                  <div className="flex items-start justify-between gap-2 mb-1">
                    <h4 className="text-sm font-medium leading-snug">{tp.title}</h4>
                    <Badge variant="outline" className={`shrink-0 ${severityColors[tp.severity]}`}>
                      {tp.severity}
                    </Badge>
                  </div>
                  <div className="flex items-center gap-2 flex-wrap mt-2">
                    <Badge variant="outline" className={`text-[10px] ${sourceColors[tp.source]}`}>
                      {sourceLabels[tp.source] || tp.source}
                    </Badge>
                    <Badge variant="secondary" className="text-[10px]">
                      {tp.policyRule.action.toUpperCase()}
                    </Badge>
                    {tp.cveId && (
                      <Badge variant="outline" className="text-[10px] bg-red-500/5 text-red-400 border-red-500/20">
                        {tp.cveId}
                      </Badge>
                    )}
                    {tp.cmmc.map(c => (
                      <Badge key={c} variant="outline" className="text-[10px]">{c}</Badge>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {status?.recentTasks && status.recentTasks.length > 0 && (
        <Card data-testid="card-recent-tasks">
          <CardHeader className="pb-3">
            <CardTitle className="text-base flex items-center gap-2">
              <Activity className="w-4 h-4 text-primary" />
              Recent Tasks
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {status.recentTasks.map((task) => (
                <div
                  key={task.id}
                  className="flex items-center justify-between py-2 px-3 rounded-md border bg-card"
                  data-testid={`task-${task.id}`}
                >
                  <div className="flex items-center gap-2">
                    {task.status === "completed" ? (
                      <CheckCircle className="w-4 h-4 text-emerald-400" />
                    ) : (
                      <XCircle className="w-4 h-4 text-red-400" />
                    )}
                    <span className="text-sm font-mono">{task.name}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    {task.error && (
                      <span className="text-xs text-red-400 max-w-[200px] truncate">{task.error}</span>
                    )}
                    <span className="text-xs text-muted-foreground">
                      {task.completedAt ? formatAgo(task.completedAt) : "pending"}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      <Card data-testid="card-architecture">
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Architecture</CardTitle>
          <CardDescription>How the autonomous engine connects to the Aiglos runtime</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-5 gap-3 text-center text-xs">
            {[
              { icon: Cpu, label: "Engine", desc: "Orchestrator / State Machine", color: "text-primary" },
              { icon: Clock, label: "Scheduler", desc: "Scan 5m / Intel 1h", color: "text-blue-400" },
              { icon: Eye, label: "Intel", desc: "NVD + OWASP + Internal", color: "text-purple-400" },
              { icon: Scan, label: "Hunter", desc: "5 Hunt Modules", color: "text-orange-400" },
              { icon: Shield, label: "Watchdog", desc: "Self-Healing Monitor", color: "text-emerald-400" },
            ].map(({ icon: Icon, label, desc, color }) => (
              <div key={label} className="p-3 rounded-lg border bg-card flex flex-col items-center gap-2">
                <Icon className={`w-6 h-6 ${color}`} />
                <span className="font-medium text-sm">{label}</span>
                <span className="text-muted-foreground">{desc}</span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
