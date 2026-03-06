import { Link, useLocation } from "wouter";
import {
  Shield,
  LayoutDashboard,
  Activity,
  AlertTriangle,
  Server,
  FileCheck,
  ScrollText,
  Moon,
  Sun,
  Users,
  Bell,
  Database,
  FileText,
  ClipboardList,
  LogOut,
  Cpu,
} from "lucide-react";
import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarHeader,
  SidebarFooter,
} from "@/components/ui/sidebar";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useTheme } from "@/components/theme-provider";
import { useAuth } from "@/lib/auth";

const monitoringItems = [
  { title: "Dashboard", url: "/", icon: LayoutDashboard },
  { title: "Command Center", url: "/engine", icon: Cpu },
  { title: "Sessions", url: "/sessions", icon: Activity },
  { title: "Events", url: "/events", icon: AlertTriangle },
  { title: "Trust Registry", url: "/trust", icon: Server },
  { title: "Policies", url: "/policies", icon: ScrollText },
  { title: "Compliance", url: "/compliance", icon: FileCheck },
];

const adminItems = [
  { title: "Users", url: "/users", icon: Users, roles: ["admin"] },
  { title: "Audit Trail", url: "/audit", icon: ClipboardList, roles: ["admin"] },
  { title: "Data Retention", url: "/retention", icon: Database, roles: ["admin"] },
  { title: "Alerting", url: "/alerts", icon: Bell, roles: ["admin", "analyst"] },
  { title: "Reports", url: "/reports", icon: FileText },
];

export function AppSidebar() {
  const [location] = useLocation();
  const { theme, toggleTheme } = useTheme();
  const { user, logout, isAdmin, isAnalyst } = useAuth();

  const roleColors: Record<string, string> = {
    admin: "bg-red-500/10 text-red-500",
    analyst: "bg-blue-500/10 text-blue-500",
    viewer: "bg-gray-500/10 text-gray-400",
  };

  return (
    <Sidebar>
      <SidebarHeader className="p-4">
        <Link href="/">
          <div className="flex items-center gap-2 cursor-pointer" data-testid="link-logo">
            <div className="w-8 h-8 rounded-md bg-primary flex items-center justify-center">
              <Shield className="w-5 h-5 text-primary-foreground" />
            </div>
            <div>
              <h1 className="text-sm font-semibold tracking-tight">Aiglos</h1>
              <p className="text-[10px] text-muted-foreground leading-none">Security Runtime</p>
            </div>
          </div>
        </Link>
      </SidebarHeader>
      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupLabel>Monitoring</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {monitoringItems.map((item) => {
                const isActive =
                  item.url === "/"
                    ? location === "/"
                    : location.startsWith(item.url);
                return (
                  <SidebarMenuItem key={item.title}>
                    <SidebarMenuButton
                      asChild
                      data-active={isActive}
                      className="data-[active=true]:bg-sidebar-accent"
                    >
                      <Link href={item.url} data-testid={`link-nav-${item.title.toLowerCase().replace(/\s+/g, "-")}`}>
                        <item.icon className={isActive ? "text-primary" : ""} />
                        <span>{item.title}</span>
                      </Link>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                );
              })}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>

        <SidebarGroup>
          <SidebarGroupLabel>Administration</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {adminItems
                .filter(item => {
                  if (!item.roles) return true;
                  if (item.roles.includes("admin") && isAdmin) return true;
                  if (item.roles.includes("analyst") && isAnalyst) return true;
                  return false;
                })
                .map((item) => {
                  const isActive = location.startsWith(item.url);
                  return (
                    <SidebarMenuItem key={item.title}>
                      <SidebarMenuButton
                        asChild
                        data-active={isActive}
                        className="data-[active=true]:bg-sidebar-accent"
                      >
                        <Link href={item.url} data-testid={`link-nav-${item.title.toLowerCase().replace(/\s+/g, "-")}`}>
                          <item.icon className={isActive ? "text-primary" : ""} />
                          <span>{item.title}</span>
                        </Link>
                      </SidebarMenuButton>
                    </SidebarMenuItem>
                  );
                })}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>
      <SidebarFooter className="p-4 space-y-3">
        {user && (
          <div className="flex items-center gap-2 px-1">
            <div className="w-7 h-7 rounded-full bg-primary/10 flex items-center justify-center flex-shrink-0">
              <span className="text-xs font-medium text-primary">
                {(user.displayName || user.username).charAt(0).toUpperCase()}
              </span>
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-xs font-medium truncate">{user.displayName || user.username}</p>
              <Badge variant="outline" className={`text-[9px] py-0 ${roleColors[user.role] || ""}`}>
                {user.role}
              </Badge>
            </div>
          </div>
        )}
        <div className="flex items-center justify-between gap-1">
          <Button
            size="icon"
            variant="ghost"
            onClick={logout}
            data-testid="button-logout"
            className="h-8 w-8"
          >
            <LogOut className="w-4 h-4" />
          </Button>
          <span className="text-xs text-muted-foreground">v1.0.0</span>
          <Button
            size="icon"
            variant="ghost"
            onClick={toggleTheme}
            data-testid="button-theme-toggle"
            className="h-8 w-8"
          >
            {theme === "dark" ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
          </Button>
        </div>
      </SidebarFooter>
    </Sidebar>
  );
}
