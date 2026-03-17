import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ScrollText, User, Clock } from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { useState } from "react";
import type { AuditLog } from "@shared/schema";

const actionColors: Record<string, string> = {
  login: "bg-blue-500/10 text-blue-500",
  logout: "bg-gray-500/10 text-gray-500",
  create: "bg-emerald-500/10 text-emerald-500",
  update: "bg-amber-500/10 text-amber-500",
  delete: "bg-red-500/10 text-red-500",
  create_user: "bg-emerald-500/10 text-emerald-500",
  update_user: "bg-amber-500/10 text-amber-500",
  delete_user: "bg-red-500/10 text-red-500",
  export: "bg-purple-500/10 text-purple-500",
  purge: "bg-red-500/10 text-red-500",
};

export default function AuditLogs() {
  const [resourceFilter, setResourceFilter] = useState<string>("all");

  const queryParams = resourceFilter !== "all" ? `?resourceType=${resourceFilter}` : "";
  const { data: logs, isLoading } = useQuery<AuditLog[]>({
    queryKey: ["/api/audit-logs", queryParams],
  });

  return (
    <div className="p-6 space-y-6 max-w-[1400px] mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-semibold tracking-tight" data-testid="text-audit-title">Audit Trail</h2>
        </div>
        <Select value={resourceFilter} onValueChange={setResourceFilter}>
          <SelectTrigger className="w-[180px]" data-testid="select-resource-filter">
            <SelectValue placeholder="Filter by resource" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Resources</SelectItem>
            <SelectItem value="auth">Authentication</SelectItem>
            <SelectItem value="user">Users</SelectItem>
            <SelectItem value="policy_rule">Policies</SelectItem>
            <SelectItem value="trusted_server">Servers</SelectItem>
            <SelectItem value="alert_destination">Alerts</SelectItem>
            <SelectItem value="retention_policy">Retention</SelectItem>
            <SelectItem value="report">Reports</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <ScrollText className="w-4 h-4" />
            Activity Log ({logs?.length || 0} entries)
          </CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="space-y-3">
              {Array.from({ length: 5 }).map((_, i) => (
                <Skeleton key={i} className="h-14 w-full" />
              ))}
            </div>
          ) : logs && logs.length > 0 ? (
            <div className="space-y-1">
              {logs.map((log) => (
                <div
                  key={log.id}
                  className="flex items-center gap-3 p-3 rounded-md hover:bg-muted/50 transition-colors"
                  data-testid={`audit-row-${log.id}`}
                >
                  <div className="flex-shrink-0">
                    <User className="w-4 h-4 text-muted-foreground" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-sm font-medium">{log.username}</span>
                      <Badge variant="outline" className={actionColors[log.action] || "bg-muted"}>
                        {log.action}
                      </Badge>
                      <span className="text-sm text-muted-foreground">{log.resourceType}</span>
                      {log.resourceId && (
                        <span className="text-xs font-mono text-muted-foreground/70 truncate max-w-[200px]">
                          {log.resourceId}
                        </span>
                      )}
                    </div>
                    {log.details && Object.keys(log.details as object).length > 0 && (
                      <p className="text-xs text-muted-foreground mt-0.5 truncate">
                        {JSON.stringify(log.details)}
                      </p>
                    )}
                  </div>
                  <div className="flex items-center gap-1 text-xs text-muted-foreground whitespace-nowrap flex-shrink-0">
                    <Clock className="w-3 h-3" />
                    {formatDistanceToNow(new Date(log.timestamp), { addSuffix: true })}
                  </div>
                  {log.ipAddress && (
                    <span className="text-[10px] font-mono text-muted-foreground/50 flex-shrink-0">
                      {log.ipAddress}
                    </span>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground text-center py-12">No audit entries</p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
