import { Switch, Route, useLocation } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { ThemeProvider } from "@/components/theme-provider";
import { AuthProvider, useAuth } from "@/lib/auth";
import { SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { AppSidebar } from "@/components/app-sidebar";
import NotFound from "@/pages/not-found";
import Login from "@/pages/login";
import Dashboard from "@/pages/dashboard";
import Sessions from "@/pages/sessions";
import Events from "@/pages/events";
import TrustRegistry from "@/pages/trust";
import Policies from "@/pages/policies";
import Compliance from "@/pages/compliance";
import AuditLogs from "@/pages/audit-logs";
import Retention from "@/pages/retention";
import Alerting from "@/pages/alerting";
import UsersPage from "@/pages/users";
import Reports from "@/pages/reports";
import EnginePage from "@/pages/engine";
import { Skeleton } from "@/components/ui/skeleton";

import PublicLayout from "@/components/public-layout";
import HomePage from "@/pages/home";
import AiglosScan from "@/pages/aiglos_scan";
import GovBench from "@/pages/aiglos_govbench";
import AiglosIntel from "@/pages/aiglos_intel";
import AiglosCompliance from "@/pages/aiglos_compliance";
import ComparePage from "@/pages/compare";
import PricingPage from "@/pages/pricing";
import ReferencePage from "@/pages/reference";

const PUBLIC_PATHS = ["/", "/scan", "/govbench", "/intel", "/compliance", "/compare", "/pricing", "/reference"];

function isPublicPath(path: string) {
  const normalized = path.replace(/\/+$/, "") || "/";
  return PUBLIC_PATHS.includes(normalized);
}

function DashboardRouter() {
  return (
    <Switch>
      <Route path="/dashboard" component={Dashboard} />
      <Route path="/sessions" component={Sessions} />
      <Route path="/events" component={Events} />
      <Route path="/trust" component={TrustRegistry} />
      <Route path="/policies" component={Policies} />
      <Route path="/dashboard/compliance" component={Compliance} />
      <Route path="/engine" component={EnginePage} />
      <Route path="/audit" component={AuditLogs} />
      <Route path="/retention" component={Retention} />
      <Route path="/alerts" component={Alerting} />
      <Route path="/users" component={UsersPage} />
      <Route path="/reports" component={Reports} />
      <Route component={NotFound} />
    </Switch>
  );
}

const sidebarStyle = {
  "--sidebar-width": "15rem",
  "--sidebar-width-icon": "3rem",
};

function AuthenticatedApp() {
  const { user, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="flex h-screen items-center justify-center">
        <div className="space-y-3 w-48">
          <Skeleton className="h-4 w-full" />
          <Skeleton className="h-4 w-3/4" />
          <Skeleton className="h-4 w-1/2" />
        </div>
      </div>
    );
  }

  if (!user) {
    return <Login />;
  }

  return (
    <SidebarProvider style={sidebarStyle as React.CSSProperties}>
      <div className="flex h-screen w-full">
        <AppSidebar />
        <div className="flex flex-col flex-1 min-w-0">
          <header className="flex items-center gap-2 p-2 border-b h-11">
            <SidebarTrigger data-testid="button-sidebar-toggle" />
          </header>
          <main className="flex-1 overflow-auto">
            <DashboardRouter />
          </main>
        </div>
      </div>
    </SidebarProvider>
  );
}

function PublicPages() {
  return (
    <PublicLayout>
      <Switch>
        <Route path="/" component={HomePage} />
        <Route path="/scan" component={AiglosScan} />
        <Route path="/govbench" component={GovBench} />
        <Route path="/intel" component={AiglosIntel} />
        <Route path="/compliance" component={AiglosCompliance} />
        <Route path="/compare" component={ComparePage} />
        <Route path="/pricing" component={PricingPage} />
        <Route path="/reference" component={ReferencePage} />
      </Switch>
    </PublicLayout>
  );
}

function AppRouter() {
  const [location] = useLocation();

  if (isPublicPath(location)) {
    return <PublicPages />;
  }

  return <AuthenticatedApp />;
}

function App() {
  return (
    <ThemeProvider>
      <QueryClientProvider client={queryClient}>
        <TooltipProvider>
          <AuthProvider>
            <AppRouter />
          </AuthProvider>
          <Toaster />
        </TooltipProvider>
      </QueryClientProvider>
    </ThemeProvider>
  );
}

export default App;
