/**
 * signup.js — Netlify Function
 * Handles POST /api/signup
 *
 * Free tier signups — capture email, send onboarding sequence.
 *
 * Email provider: Resend (https://resend.com)
 *   Set RESEND_API_KEY in Netlify environment variables.
 *   If not set, logs the email and returns success (dev mode).
 *
 * Optional: Supabase for lead storage
 *   Set SUPABASE_URL and SUPABASE_ANON_KEY.
 */

const ONBOARDING_FROM = "Aiglos <hello@aiglos.dev>";
const ONBOARDING_SUBJECT = "Your Aiglos install — quick start";

function buildOnboardingEmail(name) {
  const greeting = name ? `Hi ${name},` : "Hi,";
  return {
    text: `${greeting}

Welcome to Aiglos. You're on the free tier — 10,000 tool calls/month,
full T01-T39 detection, zero telemetry, no API key required.

Quick start:

  pip install aiglos

  import aiglos
  aiglos.attach()          # one line — MCP, HTTP, subprocess all covered
  # ... your agent runs ...
  artifact = aiglos.close()  # signed session artifact

That's it. Every tool call is now scanned and signed.

When you're ready for cloud telemetry, RSA-2048 signed artifacts,
and compliance exports: https://aiglos.dev/#pricing

Documentation: https://docs.aiglos.dev
CVE library:   https://github.com/aiglos/aiglos
Questions:     security@aiglos.dev

-- The Aiglos team`,

    html: `<p>${greeting}</p>
<p>Welcome to Aiglos. You're on the free tier — 10,000 tool calls/month,
full T01-T39 detection, zero telemetry, no API key required.</p>
<pre style="background:#0a0a0f;color:#e2e8f0;padding:16px;border-radius:8px;font-size:13px">
pip install aiglos

import aiglos
aiglos.attach()          # one line — all surfaces covered
# ... your agent runs ...
artifact = aiglos.close()  # signed session artifact
</pre>
<p>That's it. Every tool call is now scanned and signed.</p>
<p>When you're ready for cloud telemetry and compliance exports:
<a href="https://aiglos.dev/#pricing">aiglos.dev/#pricing</a></p>
<p>— The Aiglos team</p>`,
  };
}

exports.handler = async (event) => {
  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 200, body: "" };
  }
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, body: "Method Not Allowed" };
  }

  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Content-Type": "application/json",
  };

  try {
    const { email, name, plan } = JSON.parse(event.body || "{}");
    if (!email) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: "Email required" }),
      };
    }

    const emailBody = buildOnboardingEmail(name);

    // ── 1. Send onboarding email via Resend ──────────────────────────────────
    if (process.env.RESEND_API_KEY) {
      const res = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
        },
        body: JSON.stringify({
          from:    ONBOARDING_FROM,
          to:      [email],
          subject: ONBOARDING_SUBJECT,
          text:    emailBody.text,
          html:    emailBody.html,
        }),
      });
      if (!res.ok) {
        const err = await res.text();
        console.error("[signup] Resend error:", err);
        // Non-fatal — still record the signup
      } else {
        console.log(`[signup] Onboarding email sent to ${email}`);
      }
    } else {
      console.log(`[signup] RESEND_API_KEY not set — skipping email for ${email}`);
    }

    // ── 2. Store lead in Supabase (optional) ─────────────────────────────────
    if (process.env.SUPABASE_URL && process.env.SUPABASE_ANON_KEY) {
      try {
        const { createClient } = require("@supabase/supabase-js");
        const supabase = createClient(
          process.env.SUPABASE_URL,
          process.env.SUPABASE_ANON_KEY
        );
        await supabase.from("signups").insert({
          email,
          name:       name || null,
          plan:       plan || "free",
          created_at: new Date().toISOString(),
          source:     event.headers.referer || "direct",
        });
      } catch (dbErr) {
        console.error("[signup] Supabase error:", dbErr.message);
        // Non-fatal
      }
    }

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ success: true }),
    };
  } catch (err) {
    console.error("[signup] Error:", err.message);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: "Internal error" }),
    };
  }
};
