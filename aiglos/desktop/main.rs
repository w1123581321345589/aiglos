// Aiglos Desktop -- Tauri application
// System tray icon, real-time alert feed, Tier 3 approval UI,
// compliance report export.
//
// Architecture:
//   Rust (Tauri) -- OS integration layer:
//     - System tray icon with alert count badge
//     - Native notifications for T37/T43/T41 CRITICAL events
//     - File system watcher for aiglos event log
//     - IPC bridge between React frontend and Python sidecar
//
//   Python sidecar -- aiglos runtime:
//     - Full aiglos package running as a subprocess
//     - Emits JSON events to stdout for Tauri to consume
//     - Receives commands from Tauri via stdin
//     - All intelligence: baseline, federation, proposals, honeypot
//
//   React frontend -- UI layer:
//     - Real-time alert feed
//     - Tier 3 approval modal (override challenge display)
//     - Policy proposal review queue
//     - Compliance report viewer
//     - One-click report export

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tauri::{
    AppHandle, CustomMenuItem, Manager, SystemTray, SystemTrayEvent, SystemTrayMenu,
    SystemTrayMenuItem,
};

// ── Event types from Python sidecar ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AiglosEvent {
    Alert {
        rule_id:    String,
        threat_name: String,
        tool_name:  String,
        agent_name: String,
        severity:   String,   // LOW | MEDIUM | HIGH | CRITICAL
        score:      f64,
        session_id: String,
        timestamp:  f64,
    },
    Tier3Block {
        rule_id:       String,
        tool_name:     String,
        agent_name:    String,
        challenge_id:  String,
        code:          String,
        expires_in:    u64,
        reason:        String,
    },
    PolicyProposal {
        proposal_id:   String,
        proposal_type: String,
        agent_name:    String,
        rule_id:       String,
        confidence:    f64,
        block_count:   u32,
    },
    HoneypotHit {
        honeypot_name: String,
        agent_name:    String,
        tool_name:     String,
        session_id:    String,
    },
    BaselineAnomaly {
        agent_name:  String,
        composite:   f64,
        risk:        String,
        narrative:   String,
    },
    SessionClosed {
        session_id:    String,
        agent_name:    String,
        blocked:       u32,
        warned:        u32,
        allowed:       u32,
    },
    ComplianceReport {
        path:          String,
        coverage:      f64,
        verified:      u32,
        total:         u32,
    },
}

// ── App state ─────────────────────────────────────────────────────────────────

#[derive(Default)]
struct AppState {
    alert_count:     u32,
    pending_overrides: Vec<String>,   // challenge_ids awaiting human response
}

// ── System tray setup ─────────────────────────────────────────────────────────

fn build_tray() -> SystemTray {
    let show       = CustomMenuItem::new("show".to_string(), "Show Dashboard");
    let alerts     = CustomMenuItem::new("alerts".to_string(), "No alerts");
    let report     = CustomMenuItem::new("report".to_string(), "Generate Compliance Report");
    let separator  = SystemTrayMenuItem::Separator;
    let quit       = CustomMenuItem::new("quit".to_string(), "Quit Aiglos");

    let menu = SystemTrayMenu::new()
        .add_item(show)
        .add_item(alerts)
        .add_native_item(separator)
        .add_item(report)
        .add_native_item(SystemTrayMenuItem::Separator)
        .add_item(quit);

    SystemTray::new().with_menu(menu)
}

// ── Tauri commands (called from React frontend) ───────────────────────────────

#[tauri::command]
fn confirm_override(
    challenge_id: String,
    code: String,
    app: AppHandle,
) -> Result<bool, String> {
    // Send to Python sidecar via stdin
    let cmd = serde_json::json!({
        "action": "confirm_override",
        "challenge_id": challenge_id,
        "code": code,
    });
    // In production this sends to the Python sidecar process stdin
    // For now emit an event back to the frontend
    app.emit_all("override_response", serde_json::json!({
        "challenge_id": challenge_id,
        "approved": true,   // sidecar will validate actual code
    })).map_err(|e| e.to_string())?;
    Ok(true)
}

#[tauri::command]
fn reject_override(challenge_id: String, app: AppHandle) -> Result<(), String> {
    app.emit_all("override_response", serde_json::json!({
        "challenge_id": challenge_id,
        "approved": false,
    })).map_err(|e| e.to_string())
}

#[tauri::command]
fn approve_proposal(proposal_id: String, reviewer: String, app: AppHandle) -> Result<(), String> {
    app.emit_all("proposal_response", serde_json::json!({
        "proposal_id": proposal_id,
        "action": "approve",
        "reviewer": reviewer,
    })).map_err(|e| e.to_string())
}

#[tauri::command]
fn reject_proposal(proposal_id: String, reviewer: String, app: AppHandle) -> Result<(), String> {
    app.emit_all("proposal_response", serde_json::json!({
        "proposal_id": proposal_id,
        "action": "reject",
        "reviewer": reviewer,
    })).map_err(|e| e.to_string())
}

#[tauri::command]
fn generate_report(app: AppHandle) -> Result<(), String> {
    app.emit_all("generate_report", serde_json::json!({}))
       .map_err(|e| e.to_string())
}

#[tauri::command]
fn get_alert_count(state: tauri::State<Arc<Mutex<AppState>>>) -> u32 {
    state.lock().unwrap().alert_count
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    let state = Arc::new(Mutex::new(AppState::default()));

    tauri::Builder::default()
        .manage(state.clone())
        .system_tray(build_tray())
        .on_system_tray_event(move |app, event| match event {
            SystemTrayEvent::MenuItemClick { id, .. } => match id.as_str() {
                "show" => {
                    if let Some(window) = app.get_window("main") {
                        window.show().ok();
                        window.set_focus().ok();
                    }
                }
                "report" => {
                    app.emit_all("generate_report", serde_json::json!({})).ok();
                }
                "quit" => {
                    std::process::exit(0);
                }
                _ => {}
            },
            SystemTrayEvent::LeftClick { .. } => {
                if let Some(window) = app.get_window("main") {
                    let visible = window.is_visible().unwrap_or(false);
                    if visible {
                        window.hide().ok();
                    } else {
                        window.show().ok();
                        window.set_focus().ok();
                    }
                }
            }
            _ => {}
        })
        .invoke_handler(tauri::generate_handler![
            confirm_override,
            reject_override,
            approve_proposal,
            reject_proposal,
            generate_report,
            get_alert_count,
        ])
        .run(tauri::generate_context!())
        .expect("error while running aiglos desktop");
}
