import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Database, Trash2, AlertTriangle, Loader2 } from "lucide-react";
import { useState } from "react";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import type { DataRetentionPolicy } from "@shared/schema";

export default function Retention() {
  const { toast } = useToast();
  const [purgeType, setPurgeType] = useState("security_events");
  const [purgeDays, setPurgeDays] = useState("90");
  const [showPurgeDialog, setShowPurgeDialog] = useState(false);

  const { data: policies, isLoading } = useQuery<DataRetentionPolicy[]>({
    queryKey: ["/api/retention"],
  });

  const updateMutation = useMutation({
    mutationFn: async ({ id, data }: { id: string; data: any }) => {
      await apiRequest("PATCH", `/api/retention/${id}`, data);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/retention"] });
      toast({ title: "Retention policy updated" });
    },
  });

  const purgeMutation = useMutation({
    mutationFn: async (data: { resourceType: string; olderThanDays: number }) => {
      const res = await apiRequest("POST", "/api/retention/purge", data);
      return res.json();
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["/api/retention"] });
      setShowPurgeDialog(false);
      toast({ title: "Data purged", description: `Removed ${data.deleted} records` });
    },
  });

  const resourceLabels: Record<string, string> = {
    security_events: "Security Events",
    sessions: "Sessions",
    tool_calls: "Tool Calls",
    audit_logs: "Audit Logs",
  };

  return (
    <div className="p-6 space-y-6 max-w-[1400px] mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-semibold tracking-tight" data-testid="text-retention-title">Data Retention</h2>
          <p className="text-sm text-muted-foreground mt-1">Configure data lifecycle and archival policies</p>
        </div>
        <Dialog open={showPurgeDialog} onOpenChange={setShowPurgeDialog}>
          <DialogTrigger asChild>
            <Button variant="destructive" size="sm" data-testid="button-manual-purge">
              <Trash2 className="w-4 h-4 mr-2" />
              Manual Purge
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-destructive" />
                Manual Data Purge
              </DialogTitle>
            </DialogHeader>
            <div className="space-y-4 pt-2">
              <div className="space-y-2">
                <Label>Resource Type</Label>
                <Select value={purgeType} onValueChange={setPurgeType}>
                  <SelectTrigger data-testid="select-purge-type">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="security_events">Security Events</SelectItem>
                    <SelectItem value="sessions">Sessions</SelectItem>
                    <SelectItem value="tool_calls">Tool Calls</SelectItem>
                    <SelectItem value="audit_logs">Audit Logs</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>Older than (days)</Label>
                <Input
                  type="number"
                  value={purgeDays}
                  onChange={(e) => setPurgeDays(e.target.value)}
                  min="1"
                  data-testid="input-purge-days"
                />
              </div>
              <p className="text-xs text-destructive">This action cannot be undone. All matching records will be permanently deleted.</p>
              <Button
                variant="destructive"
                className="w-full"
                disabled={purgeMutation.isPending}
                onClick={() => purgeMutation.mutate({ resourceType: purgeType, olderThanDays: parseInt(purgeDays) })}
                data-testid="button-confirm-purge"
              >
                {purgeMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : null}
                Purge Data
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {isLoading ? (
          Array.from({ length: 4 }).map((_, i) => (
            <Card key={i}>
              <CardContent className="p-6">
                <Skeleton className="h-24 w-full" />
              </CardContent>
            </Card>
          ))
        ) : policies?.map((policy) => (
          <Card key={policy.id} data-testid={`retention-card-${policy.id}`}>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Database className="w-4 h-4" />
                  {resourceLabels[policy.resourceType] || policy.resourceType}
                </div>
                <Switch
                  checked={policy.enabled}
                  onCheckedChange={(enabled) => updateMutation.mutate({ id: policy.id, data: { enabled } })}
                  data-testid={`switch-retention-${policy.id}`}
                />
              </CardTitle>
            </CardHeader>
            <CardContent className="pt-0 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">Retention period</span>
                <Badge variant="outline">{policy.retentionDays} days</Badge>
              </div>
              <div className="flex items-center gap-2">
                <Input
                  type="number"
                  value={policy.retentionDays}
                  onChange={(e) => {
                    const val = parseInt(e.target.value);
                    if (val > 0) updateMutation.mutate({ id: policy.id, data: { retentionDays: val } });
                  }}
                  className="w-24 h-8 text-sm"
                  min="1"
                  data-testid={`input-days-${policy.id}`}
                />
                <span className="text-xs text-muted-foreground">days</span>
              </div>
              {policy.lastPurgedAt && (
                <p className="text-xs text-muted-foreground">
                  Last purged: {new Date(policy.lastPurgedAt).toLocaleDateString()}
                </p>
              )}
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
