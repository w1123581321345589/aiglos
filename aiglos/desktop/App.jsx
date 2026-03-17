// Aiglos Desktop -- Main Dashboard
// Real-time alert feed, Tier 3 approval modal, policy proposal queue,
// compliance report viewer.

import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/tauri";
import { listen } from "@tauri-apps/api/event";
import { sendNotification } from "@tauri-apps/api/notification";

// ── Alert severity colors ─────────────────────────────────────────────────────
const SEVERITY_COLORS = {
  CRITICAL: "text-red-400 bg-red-950 border-red-800",
  HIGH:     "text-orange-400 bg-orange-950 border-orange-800",
  MEDIUM:   "text-yellow-400 bg-yellow-950 border-yellow-800",
  LOW:      "text-blue-400 bg-blue-950 border-blue-800",
};

const SEVERITY_DOT = {
  CRITICAL: "bg-red-500 animate-pulse",
  HIGH:     "bg-orange-500",
  MEDIUM:   "bg-yellow-500",
  LOW:      "bg-blue-500",
};

// ── Components ────────────────────────────────────────────────────────────────

function AlertRow({ alert }) {
  const colors = SEVERITY_COLORS[alert.severity] || SEVERITY_COLORS.LOW;
  const dot    = SEVERITY_DOT[alert.severity] || SEVERITY_DOT.LOW;
  const ts     = new Date(alert.timestamp * 1000).toLocaleTimeString();

  return (
    <div className={`flex items-start gap-3 px-4 py-3 border-b border-zinc-800 hover:bg-zinc-900 transition-colors`}>
      <div className={`mt-1.5 w-2 h-2 rounded-full flex-shrink-0 ${dot}`} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="font-mono text-xs text-zinc-500">{ts}</span>
          <span className={`font-mono text-xs px-1.5 py-0.5 rounded border ${colors}`}>
            {alert.rule_id}
          </span>
          <span className="text-xs text-zinc-400">{alert.threat_name}</span>
        </div>
        <div className="mt-0.5 text-sm text-zinc-300 truncate">
          {alert.tool_name}
          {alert.agent_name && <span className="text-zinc-500"> -- {alert.agent_name}</span>}
        </div>
      </div>
      <span className="text-xs text-zinc-600 font-mono">{(alert.score * 100).toFixed(0)}%</span>
    </div>
  );
}

function OverrideModal({ challenge, onConfirm, onReject }) {
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [remaining, setRemaining] = useState(challenge.expires_in);

  useEffect(() => {
    const timer = setInterval(() => {
      setRemaining(r => Math.max(0, r - 1));
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const handleConfirm = async () => {
    if (code.length !== 6) {
      setError("Code must be 6 characters");
      return;
    }
    try {
      const approved = await invoke("confirm_override", {
        challengeId: challenge.challenge_id,
        code: code.toUpperCase(),
      });
      onConfirm(challenge.challenge_id, approved);
    } catch (e) {
      setError(String(e));
    }
  };

  return (
    <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50">
      <div className="bg-zinc-900 border border-red-800 rounded-xl p-6 w-[480px] shadow-2xl">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-3 h-3 rounded-full bg-red-500 animate-pulse" />
          <h2 className="text-white font-semibold text-lg">Override Required</h2>
          <span className="ml-auto font-mono text-red-400 text-sm">{remaining}s</span>
        </div>

        <div className="bg-zinc-950 rounded-lg p-4 mb-4 font-mono text-sm">
          <div className="text-red-400">Rule blocked: <span className="text-white">{challenge.rule_id}</span></div>
          <div className="text-zinc-400 mt-1">Tool: <span className="text-zinc-200">{challenge.tool_name}</span></div>
          {challenge.reason && (
            <div className="text-zinc-400 mt-1">Reason: <span className="text-zinc-200">{challenge.reason}</span></div>
          )}
        </div>

        <div className="mb-4">
          <label className="text-zinc-400 text-sm mb-2 block">Enter override code to authorize:</label>
          <input
            type="text"
            value={code}
            onChange={e => setCode(e.target.value.toUpperCase().slice(0, 6))}
            placeholder="A7X2K9"
            className="w-full bg-zinc-800 border border-zinc-600 rounded-lg px-4 py-3 font-mono text-xl text-white text-center tracking-[0.5em] focus:outline-none focus:border-orange-500"
            maxLength={6}
            autoFocus
            onKeyDown={e => e.key === "Enter" && handleConfirm()}
          />
          {error && <p className="text-red-400 text-xs mt-1">{error}</p>}
        </div>

        <div className="flex gap-3">
          <button
            onClick={handleConfirm}
            disabled={code.length !== 6 || remaining === 0}
            className="flex-1 bg-orange-600 hover:bg-orange-500 disabled:bg-zinc-700 disabled:text-zinc-500 text-white rounded-lg py-2.5 font-semibold transition-colors"
          >
            Authorize
          </button>
          <button
            onClick={() => onReject(challenge.challenge_id)}
            className="flex-1 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded-lg py-2.5 font-semibold transition-colors"
          >
            Reject
          </button>
        </div>
      </div>
    </div>
  );
}

function ProposalCard({ proposal, onApprove, onReject }) {
  const confPct = Math.round(proposal.confidence * 100);
  const barW    = `${confPct}%`;

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4 mb-3">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="font-mono text-xs text-yellow-400 bg-yellow-950 px-1.5 py-0.5 rounded border border-yellow-800">
              {proposal.proposal_type}
            </span>
            <span className="text-sm text-zinc-300">{proposal.agent_name} / {proposal.rule_id}</span>
          </div>
          <div className="text-xs text-zinc-500 mt-1">
            {proposal.block_count} blocks · {confPct}% confidence
          </div>
          <div className="mt-2 h-1.5 bg-zinc-800 rounded-full overflow-hidden w-40">
            <div
              className="h-full bg-gradient-to-r from-yellow-600 to-yellow-400 rounded-full"
              style={{ width: barW }}
            />
          </div>
        </div>
        <div className="flex gap-2 flex-shrink-0">
          <button
            onClick={() => onApprove(proposal.proposal_id)}
            className="bg-green-800 hover:bg-green-700 text-green-200 text-xs px-3 py-1.5 rounded-lg font-medium transition-colors"
          >
            Approve
          </button>
          <button
            onClick={() => onReject(proposal.proposal_id)}
            className="bg-zinc-800 hover:bg-zinc-700 text-zinc-400 text-xs px-3 py-1.5 rounded-lg font-medium transition-colors"
          >
            Reject
          </button>
        </div>
      </div>
    </div>
  );
}

function StatCard({ label, value, sub, color = "text-white" }) {
  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
      <div className={`text-2xl font-bold font-mono ${color}`}>{value}</div>
      <div className="text-xs text-zinc-400 mt-0.5">{label}</div>
      {sub && <div className="text-xs text-zinc-600 mt-0.5">{sub}</div>}
    </div>
  );
}

// ── Main App ──────────────────────────────────────────────────────────────────

export default function App() {
  const [alerts, setAlerts]         = useState([]);
  const [proposals, setProposals]   = useState([]);
  const [overrides, setOverrides]   = useState([]);
  const [stats, setStats]           = useState({ blocked: 0, warned: 0, sessions: 0, honeypot: 0 });
  const [activeTab, setActiveTab]   = useState("alerts");
  const [reportPath, setReportPath] = useState(null);

  // Listen for events from Tauri / Python sidecar
  useEffect(() => {
    const unlisteners = [];

    listen("aiglos_event", (event) => {
      const data = event.payload;

      if (data.type === "Alert" || data.type === "HoneypotHit") {
        setAlerts(prev => [data, ...prev].slice(0, 200));
        if (data.severity === "CRITICAL") {
          sendNotification({
            title: `Aiglos -- ${data.rule_id || "T43"} ${data.severity}`,
            body: data.honeypot_name
              ? `Honeypot accessed: ${data.honeypot_name}`
              : `${data.threat_name} -- ${data.tool_name}`,
          });
        }
        if (data.type === "Alert") {
          setStats(s => ({
            ...s,
            blocked: s.blocked + (data.severity !== "LOW" ? 1 : 0),
          }));
        }
        if (data.type === "HoneypotHit") {
          setStats(s => ({ ...s, honeypot: s.honeypot + 1 }));
        }
      }

      if (data.type === "Tier3Block") {
        setOverrides(prev => [data, ...prev]);
        sendNotification({
          title: "Aiglos -- Override Required",
          body: `${data.rule_id}: ${data.tool_name} blocked. Code: ${data.code}`,
        });
      }

      if (data.type === "PolicyProposal") {
        setProposals(prev => {
          const exists = prev.find(p => p.proposal_id === data.proposal_id);
          if (exists) return prev;
          return [data, ...prev];
        });
      }

      if (data.type === "SessionClosed") {
        setStats(s => ({ ...s, sessions: s.sessions + 1 }));
      }

      if (data.type === "ComplianceReport") {
        setReportPath(data.path);
      }
    }).then(fn => unlisteners.push(fn));

    return () => unlisteners.forEach(fn => fn());
  }, []);

  const handleConfirmOverride = useCallback((challengeId) => {
    setOverrides(prev => prev.filter(o => o.challenge_id !== challengeId));
  }, []);

  const handleRejectOverride = useCallback(async (challengeId) => {
    await invoke("reject_override", { challengeId });
    setOverrides(prev => prev.filter(o => o.challenge_id !== challengeId));
  }, []);

  const handleApproveProposal = useCallback(async (proposalId) => {
    await invoke("approve_proposal", { proposalId, reviewer: "desktop" });
    setProposals(prev => prev.filter(p => p.proposal_id !== proposalId));
  }, []);

  const handleRejectProposal = useCallback(async (proposalId) => {
    await invoke("reject_proposal", { proposalId, reviewer: "desktop" });
    setProposals(prev => prev.filter(p => p.proposal_id !== proposalId));
  }, []);

  const handleGenerateReport = useCallback(async () => {
    await invoke("generate_report");
  }, []);

  const tabs = [
    { id: "alerts",    label: "Alerts",    badge: alerts.length },
    { id: "overrides", label: "Overrides", badge: overrides.length },
    { id: "proposals", label: "Proposals", badge: proposals.length },
    { id: "report",    label: "Compliance" },
  ];

  return (
    <div className="h-screen bg-zinc-950 text-zinc-100 flex flex-col font-sans">
      {/* Header */}
      <div className="flex items-center gap-4 px-6 py-3 border-b border-zinc-800 bg-zinc-900/50">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-green-500" />
          <span className="font-mono text-sm font-semibold text-white">Aiglos</span>
          <span className="text-xs text-zinc-600 font-mono">v0.15.0</span>
        </div>
        <div className="flex gap-4 ml-4">
          <StatCard label="sessions" value={stats.sessions} color="text-zinc-200" />
          <StatCard label="blocked"  value={stats.blocked}  color="text-orange-400" />
          <StatCard label="honeypot hits" value={stats.honeypot} color="text-red-400" />
        </div>
        <button
          onClick={handleGenerateReport}
          className="ml-auto bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs px-3 py-1.5 rounded-lg transition-colors"
        >
          Export Report
        </button>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-zinc-800 bg-zinc-900/30">
        {tabs.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-5 py-2.5 text-sm font-medium transition-colors relative ${
              activeTab === tab.id
                ? "text-white border-b-2 border-orange-500"
                : "text-zinc-500 hover:text-zinc-300"
            }`}
          >
            {tab.label}
            {tab.badge > 0 && (
              <span className="ml-1.5 bg-orange-600 text-white text-xs rounded-full px-1.5 py-0.5 font-mono">
                {tab.badge}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto">
        {activeTab === "alerts" && (
          <div>
            {alerts.length === 0 ? (
              <div className="flex items-center justify-center h-64 text-zinc-600">
                No alerts yet -- agents are running clean
              </div>
            ) : (
              alerts.map((a, i) => (
                <AlertRow key={`${a.session_id}-${i}`} alert={a} />
              ))
            )}
          </div>
        )}

        {activeTab === "overrides" && (
          <div className="p-4">
            {overrides.length === 0 ? (
              <div className="flex items-center justify-center h-64 text-zinc-600">
                No pending overrides
              </div>
            ) : (
              overrides.map(o => (
                <div key={o.challenge_id} className="mb-3 bg-red-950/30 border border-red-800/50 rounded-lg p-4">
                  <div className="font-mono text-red-400 text-sm mb-1">{o.rule_id} -- {o.tool_name}</div>
                  <div className="text-white font-mono text-2xl tracking-widest mb-3">{o.code}</div>
                  <div className="flex gap-2">
                    <button
                      onClick={() => handleRejectOverride(o.challenge_id)}
                      className="bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs px-3 py-1.5 rounded-lg"
                    >
                      Reject
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        )}

        {activeTab === "proposals" && (
          <div className="p-4">
            {proposals.length === 0 ? (
              <div className="flex items-center justify-center h-64 text-zinc-600">
                No pending policy proposals
              </div>
            ) : (
              proposals.map(p => (
                <ProposalCard
                  key={p.proposal_id}
                  proposal={p}
                  onApprove={handleApproveProposal}
                  onReject={handleRejectProposal}
                />
              ))
            )}
          </div>
        )}

        {activeTab === "report" && (
          <div className="p-6">
            <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-6">
              <h3 className="text-white font-semibold mb-4">Compliance Report</h3>
              <p className="text-zinc-400 text-sm mb-4">
                Generates an audit-ready compliance report mapping all active rules
                to NDAA §1513, EU AI Act Annex III, and NIST AI 600-1 requirements.
              </p>
              <button
                onClick={handleGenerateReport}
                className="bg-orange-600 hover:bg-orange-500 text-white px-4 py-2 rounded-lg font-medium transition-colors"
              >
                Generate Report
              </button>
              {reportPath && (
                <div className="mt-4 bg-zinc-950 rounded p-3 font-mono text-xs text-green-400">
                  ✓ Report saved: {reportPath}
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Override modals */}
      {overrides
        .filter(o => o.code)
        .map(o => (
          <OverrideModal
            key={o.challenge_id}
            challenge={o}
            onConfirm={handleConfirmOverride}
            onReject={handleRejectOverride}
          />
        ))}
    </div>
  );
}
