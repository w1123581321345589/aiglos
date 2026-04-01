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
import { Bell, Plus, Trash2, Send, Loader2, Webhook, Mail } from "lucide-react";
import { SiSlack } from "react-icons/si";
import { useState } from "react";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/lib/auth";
import { formatDistanceToNow } from "date-fns";
import type { AlertDestination } from "@shared/schema";

const typeIcons: Record<string, any> = {
  slack: SiSlack,
  webhook: Webhook,
  email: Mail,
  splunk: Bell,
  siem: Bell,
  pagerduty: Bell,
};

export default function Alerting() {
  const { toast } = useToast();
  const { isAdmin } = useAuth();
  const [showAddDialog, setShowAddDialog] = useState(false);
  const [newName, setNewName] = useState("");
  const [newType, setNewType] = useState("webhook");
  const [newUrl, setNewUrl] = useState("");
  const [newSeverities, setNewSeverities] = useState<string[]>(["critical", "high"]);

  const { data: destinations, isLoading } = useQuery<AlertDestination[]>({
    queryKey: ["/api/alerts"],
  });

  const createMutation = useMutation({
    mutationFn: async (data: any) => {
      await apiRequest("POST", "/api/alerts", data);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/alerts"] });
      setShowAddDialog(false);
      setNewName("");
      setNewUrl("");
      toast({ title: "Alert destination created" });
    },
  });

  const updateMutation = useMutation({
    mutationFn: async ({ id, data }: { id: string; data: any }) => {
      await apiRequest("PATCH", `/api/alerts/${id}`, data);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/alerts"] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/alerts/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/alerts"] });
      toast({ title: "Alert destination removed" });
    },
  });

  const testMutation = useMutation({
    mutationFn: async (id: string) => {
      const res = await apiRequest("POST", `/api/alerts/${id}/test`);
      return res.json();
    },
    onSuccess: (data) => {
      toast({
        title: data.success ? "Test alert sent" : "Test failed",
        description: data.success ? `Status: ${data.status}` : data.error,
        variant: data.success ? "default" : "destructive",
      });
    },
  });

  const toggleSeverity = (sev: string) => {
    setNewSeverities(prev =>
      prev.includes(sev) ? prev.filter(s => s !== sev) : [...prev, sev]
    );
  };

  return (
    <div className="p-6 space-y-6 max-w-[1400px] mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-semibold tracking-tight" data-testid="text-alerting-title">Alert Destinations</h2>
        </div>
        {isAdmin && (
          <Dialog open={showAddDialog} onOpenChange={setShowAddDialog}>
            <DialogTrigger asChild>
              <Button size="sm" data-testid="button-add-destination">
                <Plus className="w-4 h-4 mr-2" />
                Add Destination
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Add Alert Destination</DialogTitle>
              </DialogHeader>
              <div className="space-y-4 pt-2">
                <div className="space-y-2">
                  <Label>Name</Label>
                  <Input
                    value={newName}
                    onChange={(e) => setNewName(e.target.value)}
                    placeholder="e.g., Security Slack Channel"
                    data-testid="input-dest-name"
                  />
                </div>
                <div className="space-y-2">
                  <Label>Type</Label>
                  <Select value={newType} onValueChange={setNewType}>
                    <SelectTrigger data-testid="select-dest-type">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="slack">Slack</SelectItem>
                      <SelectItem value="webhook">Webhook</SelectItem>
                      <SelectItem value="splunk">Splunk</SelectItem>
                      <SelectItem value="siem">SIEM</SelectItem>
                      <SelectItem value="email">Email</SelectItem>
                      <SelectItem value="pagerduty">PagerDuty</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label>Webhook URL</Label>
                  <Input
                    value={newUrl}
                    onChange={(e) => setNewUrl(e.target.value)}
                    placeholder="https://hooks.slack.com/services/..."
                    data-testid="input-dest-url"
                  />
                </div>
                <div className="space-y-2">
                  <Label>Severity Filter</Label>
                  <div className="flex gap-2 flex-wrap">
                    {["critical", "high", "medium", "low", "info"].map(sev => (
                      <Badge
                        key={sev}
                        variant={newSeverities.includes(sev) ? "default" : "outline"}
                        className="cursor-pointer"
                        onClick={() => toggleSeverity(sev)}
                        data-testid={`badge-severity-${sev}`}
                      >
                        {sev}
                      </Badge>
                    ))}
                  </div>
                </div>
                <Button
                  className="w-full"
                  disabled={!newName || !newUrl || createMutation.isPending}
                  onClick={() => createMutation.mutate({
                    name: newName,
                    type: newType,
                    config: { webhookUrl: newUrl },
                    severityFilter: newSeverities,
                    enabled: true,
                  })}
                  data-testid="button-create-destination"
                >
                  {createMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : null}
                  Create Destination
                </Button>
              </div>
            </DialogContent>
          </Dialog>
        )}
      </div>

      {isLoading ? (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Card><CardContent className="p-6"><Skeleton className="h-28 w-full" /></CardContent></Card>
          <Card><CardContent className="p-6"><Skeleton className="h-24 w-full" /></CardContent></Card>
        </div>
      ) : destinations && destinations.length > 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {destinations.map((dest) => {
            const Icon = typeIcons[dest.type] || Bell;
            return (
              <Card key={dest.id} data-testid={`alert-card-${dest.id}`}>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-medium flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Icon className="w-4 h-4" />
                      {dest.name}
                    </div>
                    <div className="flex items-center gap-2">
                      {isAdmin && (
                        <Switch
                          checked={dest.enabled}
                          onCheckedChange={(enabled) => updateMutation.mutate({ id: dest.id, data: { enabled } })}
                          data-testid={`switch-alert-${dest.id}`}
                        />
                      )}
                    </div>
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex items-center gap-2">
                    <Badge variant="secondary">{dest.type}</Badge>
                    <Badge variant={dest.enabled ? "default" : "outline"}>
                      {dest.enabled ? "Active" : "Disabled"}
                    </Badge>
                  </div>
                  {dest.severityFilter && dest.severityFilter.length > 0 && (
                    <div className="flex gap-1 flex-wrap">
                      {dest.severityFilter.map(s => (
                        <Badge key={s} variant="outline" className="text-[10px]">{s}</Badge>
                      ))}
                    </div>
                  )}
                  {dest.lastTriggeredAt && (
                    <p className="text-xs text-muted-foreground">
                      Last triggered: {formatDistanceToNow(new Date(dest.lastTriggeredAt), { addSuffix: true })}
                    </p>
                  )}
                  {isAdmin && (
                    <div className="flex gap-2 pt-1">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => testMutation.mutate(dest.id)}
                        disabled={testMutation.isPending}
                        data-testid={`button-test-${dest.id}`}
                      >
                        <Send className="w-3 h-3 mr-1" />
                        Test
                      </Button>
                      <Button
                        size="sm"
                        variant="destructive"
                        onClick={() => deleteMutation.mutate(dest.id)}
                        disabled={deleteMutation.isPending}
                        data-testid={`button-delete-${dest.id}`}
                      >
                        <Trash2 className="w-3 h-3 mr-1" />
                        Remove
                      </Button>
                    </div>
                  )}
                </CardContent>
              </Card>
            );
          })}
        </div>
      ) : (
        <Card>
          <CardContent className="py-14 text-center">
            <Bell className="w-8 h-8 text-muted-foreground/30 mx-auto mb-2" />
            <p className="text-sm text-muted-foreground">No destinations configured</p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
