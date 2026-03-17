import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { FileText, FileJson, FileSpreadsheet, Shield, Activity, AlertTriangle, ScrollText, Key, Plus, Trash2, Copy, Loader2 } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/lib/auth";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { useState } from "react";
import { formatDistanceToNow } from "date-fns";

interface ReportConfig {
  title: string;
  description: string;
  endpoint: string;
  icon: any;
  formats: string[];
  adminOnly?: boolean;
}

const reports: ReportConfig[] = [
  {
    title: "Security Events",
    description: "Export all security events with severity, CMMC/NIST control mappings, and timestamps",
    endpoint: "/api/reports/events",
    icon: AlertTriangle,
    formats: ["json", "csv"],
  },
  {
    title: "Sessions",
    description: "Export all agent sessions with integrity scores, anomaly data, and tool permissions",
    endpoint: "/api/reports/sessions",
    icon: Activity,
    formats: ["json", "csv"],
  },
  {
    title: "CMMC/NIST Compliance",
    description: "Full compliance posture report with control family coverage and gap analysis",
    endpoint: "/api/reports/compliance",
    icon: Shield,
    formats: ["json"],
  },
  {
    title: "Audit Trail",
    description: "Complete audit log of all system actions, user activities, and configuration changes",
    endpoint: "/api/reports/audit",
    icon: ScrollText,
    formats: ["json", "csv"],
    adminOnly: true,
  },
];

interface ApiKeyDisplay {
  id: string;
  name: string;
  keyPrefix: string;
  organizationId: string;
  lastUsedAt: string | null;
  createdAt: string;
}

export default function Reports() {
  const { toast } = useToast();
  const { isAdmin } = useAuth();
  const [showKeyDialog, setShowKeyDialog] = useState(false);
  const [newKeyName, setNewKeyName] = useState("");
  const [newKeyValue, setNewKeyValue] = useState<string | null>(null);

  const { data: apiKeys } = useQuery<ApiKeyDisplay[]>({
    queryKey: ["/api/api-keys"],
    enabled: isAdmin,
  });

  const createKeyMutation = useMutation({
    mutationFn: async (name: string) => {
      const res = await apiRequest("POST", "/api/api-keys", { name });
      return res.json();
    },
    onSuccess: (data) => {
      setNewKeyValue(data.key);
      queryClient.invalidateQueries({ queryKey: ["/api/api-keys"] });
    },
  });

  const deleteKeyMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/api-keys/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/api-keys"] });
      toast({ title: "API key deleted" });
    },
  });

  const downloadReport = async (endpoint: string, format: string, title: string) => {
    try {
      const url = `${endpoint}?format=${format}`;
      const res = await fetch(url, { credentials: "include" });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.message || "Export failed");
      }

      if (format === "csv") {
        const blob = await res.blob();
        const downloadUrl = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = downloadUrl;
        a.download = `aiglos-${title.toLowerCase().replace(/\s+/g, "-")}-${Date.now()}.csv`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(downloadUrl);
      } else {
        const data = await res.json();
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
        const downloadUrl = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = downloadUrl;
        a.download = `aiglos-${title.toLowerCase().replace(/\s+/g, "-")}-${Date.now()}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(downloadUrl);
      }

      toast({ title: "Report downloaded", description: `${title} exported as ${format.toUpperCase()}` });
    } catch (err: any) {
      toast({ title: "Export failed", description: err.message, variant: "destructive" });
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-[1400px] mx-auto">
      <div>
        <h2 className="text-xl font-semibold tracking-tight" data-testid="text-reports-title">Reports & Export</h2>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {reports.map((report) => (
          <Card key={report.title} data-testid={`report-card-${report.title.toLowerCase().replace(/\s+/g, "-")}`}>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <report.icon className="w-4 h-4 text-primary" />
                {report.title}
                {report.adminOnly && <Badge variant="outline" className="text-[10px]">Admin</Badge>}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <p className="text-xs text-muted-foreground">{report.description}</p>
              <div className="flex gap-2">
                {report.formats.map((format) => (
                  <Button
                    key={format}
                    size="sm"
                    variant="outline"
                    onClick={() => downloadReport(report.endpoint, format, report.title)}
                    data-testid={`button-export-${report.title.toLowerCase().replace(/\s+/g, "-")}-${format}`}
                  >
                    {format === "json" ? <FileJson className="w-3 h-3 mr-1" /> : <FileSpreadsheet className="w-3 h-3 mr-1" />}
                    {format.toUpperCase()}
                  </Button>
                ))}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {isAdmin && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Key className="w-4 h-4" />
                API Keys
              </div>
              <Dialog open={showKeyDialog} onOpenChange={(open) => {
                setShowKeyDialog(open);
                if (!open) { setNewKeyValue(null); setNewKeyName(""); }
              }}>
                <DialogTrigger asChild>
                  <Button size="sm" variant="outline" data-testid="button-create-api-key">
                    <Plus className="w-3 h-3 mr-1" />
                    Generate Key
                  </Button>
                </DialogTrigger>
                <DialogContent>
                  <DialogHeader>
                    <DialogTitle>Generate API Key</DialogTitle>
                  </DialogHeader>
                  {newKeyValue ? (
                    <div className="space-y-3 pt-2">
                      <p className="text-sm text-amber-500 font-medium">Copy this key now — it won't be shown again.</p>
                      <div className="bg-muted rounded-md p-3 font-mono text-xs break-all select-all" data-testid="text-new-api-key">
                        {newKeyValue}
                      </div>
                      <Button
                        className="w-full"
                        variant="outline"
                        onClick={() => {
                          navigator.clipboard.writeText(newKeyValue);
                          toast({ title: "Copied to clipboard" });
                        }}
                        data-testid="button-copy-key"
                      >
                        <Copy className="w-4 h-4 mr-2" />
                        Copy Key
                      </Button>
                    </div>
                  ) : (
                    <div className="space-y-4 pt-2">
                      <div className="space-y-2">
                        <Label>Key Name</Label>
                        <Input
                          value={newKeyName}
                          onChange={(e) => setNewKeyName(e.target.value)}
                          placeholder="e.g., Production Proxy"
                          data-testid="input-api-key-name"
                        />
                      </div>
                      <Button
                        className="w-full"
                        disabled={!newKeyName || createKeyMutation.isPending}
                        onClick={() => createKeyMutation.mutate(newKeyName)}
                        data-testid="button-generate-key"
                      >
                        {createKeyMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : null}
                        Generate
                      </Button>
                    </div>
                  )}
                </DialogContent>
              </Dialog>
            </CardTitle>
          </CardHeader>
          <CardContent>
            {apiKeys && apiKeys.length > 0 ? (
              <div className="space-y-2">
                {apiKeys.map((k) => (
                  <div key={k.id} className="flex items-center justify-between p-2 rounded-md bg-muted/50" data-testid={`api-key-${k.id}`}>
                    <div>
                      <span className="text-sm font-medium">{k.name}</span>
                      <span className="text-xs font-mono text-muted-foreground ml-2">{k.keyPrefix}</span>
                      {k.lastUsedAt && (
                        <span className="text-[10px] text-muted-foreground ml-2">
                          Last used {formatDistanceToNow(new Date(k.lastUsedAt), { addSuffix: true })}
                        </span>
                      )}
                    </div>
                    <Button size="sm" variant="destructive" onClick={() => deleteKeyMutation.mutate(k.id)} data-testid={`button-delete-key-${k.id}`}>
                      <Trash2 className="w-3 h-3" />
                    </Button>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-muted-foreground">No API keys. Generate one to use the ingest API and WebSocket.</p>
            )}
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <FileText className="w-4 h-4" />
            API Integration
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-xs text-muted-foreground">
            Use the ingest API to push events from your Aiglos proxy runtime. Generate an API key above first.
          </p>
          <div className="bg-muted rounded-md p-3 font-mono text-xs space-y-2">
            <p className="text-muted-foreground"># Push a security event via HTTP</p>
            <p>curl -X POST {window.location.origin}/api/ingest/event \</p>
            <p className="pl-4">-H "Content-Type: application/json" \</p>
            <p className="pl-4">-H "X-API-Key: aig_YOUR_KEY_HERE" \</p>
            <p className="pl-4">-d '&#123;"sessionId":"...","eventType":"tool_call","severity":"info","title":"...","description":"..."&#125;'</p>
          </div>
          <div className="bg-muted rounded-md p-3 font-mono text-xs space-y-2">
            <p className="text-muted-foreground"># Connect via WebSocket for real-time streaming</p>
            <p>wscat -c ws://{window.location.host}/ws?apiKey=aig_YOUR_KEY_HERE</p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
