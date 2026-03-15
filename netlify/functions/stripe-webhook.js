/**
 * stripe-webhook.js — Netlify Function
 * Handles POST /api/stripe-webhook
 *
 * Stripe dashboard setup:
 *   Developers → Webhooks → Add endpoint
 *   URL: https://aiglos.dev/api/stripe-webhook
 *   Events: checkout.session.completed
 *           customer.subscription.deleted
 *           invoice.payment_failed
 *
 * Required environment variables:
 *   STRIPE_SECRET_KEY       — sk_live_xxx
 *   AIGLOS_WEBHOOK_SECRET   — whsec_xxx (from Stripe webhook dashboard)
 *   RESEND_API_KEY          — re_xxx (for key delivery email)
 *   SUPABASE_URL            — https://xxx.supabase.co
 *   SUPABASE_ANON_KEY       — eyJ...
 *
 * Supabase table required (see DEPLOY.md for full schema):
 *   api_keys (api_key, customer_email, customer_id, subscription_id,
 *             checkout_session_id, status, created_at, updated_at)
 */

const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const crypto = require("crypto");

// ── Key generation ────────────────────────────────────────────────────────────

function generateApiKey() {
  return "ak_live_" + crypto.randomBytes(24).toString("base64url");
}

// ── Supabase helper ───────────────────────────────────────────────────────────

function getSupabase() {
  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_ANON_KEY) return null;
  const { createClient } = require("@supabase/supabase-js");
  return createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);
}

// ── Key issuance ──────────────────────────────────────────────────────────────

async function issueApiKey(customerEmail, customerId, subscriptionId, checkoutSessionId) {
  const apiKey  = generateApiKey();
  const now     = new Date().toISOString();
  const supabase = getSupabase();

  if (supabase) {
    const { error } = await supabase.from("api_keys").insert({
      api_key:             apiKey,
      customer_email:      customerEmail,
      customer_id:         customerId,
      subscription_id:     subscriptionId,
      checkout_session_id: checkoutSessionId,
      status:              "active",
      created_at:          now,
      updated_at:          now,
    });
    if (error) {
      console.error("[stripe-webhook] Supabase insert error:", error.message);
      throw new Error("Failed to store API key: " + error.message);
    }
    console.log(`[stripe-webhook] API key stored for ${customerEmail}`);
  } else {
    // No storage configured — key is generated but not persisted
    // get-key.js will return 503 until Supabase is wired
    console.warn("[stripe-webhook] No Supabase configured — key not persisted:", apiKey.slice(0, 16));
  }

  await sendKeyEmail(customerEmail, apiKey);
  return apiKey;
}

// ── Key revocation ────────────────────────────────────────────────────────────

async function revokeKey(subscriptionId) {
  const supabase = getSupabase();
  if (!supabase) {
    console.warn("[stripe-webhook] No Supabase — cannot revoke key for sub:", subscriptionId);
    return;
  }
  const { error } = await supabase
    .from("api_keys")
    .update({ status: "revoked", updated_at: new Date().toISOString() })
    .eq("subscription_id", subscriptionId);
  if (error) {
    console.error("[stripe-webhook] Revoke error:", error.message);
  } else {
    console.log(`[stripe-webhook] Key revoked for subscription ${subscriptionId}`);
  }
}

// ── Key throttle (payment failed) ────────────────────────────────────────────

async function throttleKey(customerId) {
  const supabase = getSupabase();
  if (!supabase) return;
  const { error } = await supabase
    .from("api_keys")
    .update({ status: "throttled", updated_at: new Date().toISOString() })
    .eq("customer_id", customerId)
    .eq("status", "active");
  if (error) {
    console.error("[stripe-webhook] Throttle error:", error.message);
  } else {
    console.log(`[stripe-webhook] Key throttled for customer ${customerId} (payment failed)`);
  }
  await notifyPaymentFailed(customerId);
}

// ── Email delivery ────────────────────────────────────────────────────────────

async function sendKeyEmail(email, apiKey) {
  if (!process.env.RESEND_API_KEY) {
    console.log(`[stripe-webhook] RESEND_API_KEY not set — key for ${email}: ${apiKey.slice(0, 16)}...`);
    return;
  }

  const html = `
<p>Your Aiglos Pro key is ready.</p>
<pre style="background:#0a0a0f;color:#e2e8f0;padding:16px;border-radius:8px;font-family:monospace;font-size:13px">export AIGLOS_KEY=${apiKey}</pre>
<p>Quick start:</p>
<pre style="background:#0a0a0f;color:#e2e8f0;padding:16px;border-radius:8px;font-family:monospace;font-size:13px">pip install aiglos

import aiglos
aiglos.attach()          # Pro tier active
artifact = aiglos.close()  # RSA-2048 signed artifact</pre>
<p>
  <a href="https://docs.aiglos.dev">Documentation</a> ·
  <a href="https://github.com/aiglos/aiglos">GitHub</a> ·
  <a href="mailto:security@aiglos.dev">Support</a>
</p>
<p>— The Aiglos team</p>`;

  const res = await fetch("https://api.resend.com/emails", {
    method:  "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization:  `Bearer ${process.env.RESEND_API_KEY}`,
    },
    body: JSON.stringify({
      from:    "Aiglos <hello@aiglos.dev>",
      to:      [email],
      subject: "Your Aiglos Pro API key",
      html,
    }),
  });

  if (!res.ok) {
    console.error("[stripe-webhook] Resend error:", await res.text());
  } else {
    console.log(`[stripe-webhook] Key email sent to ${email}`);
  }
}

async function notifyPaymentFailed(customerId) {
  // Look up customer email and send payment failure notice
  if (!process.env.RESEND_API_KEY || !process.env.STRIPE_SECRET_KEY) return;
  try {
    const customer = await stripe.customers.retrieve(customerId);
    const email    = customer.email;
    if (!email) return;

    await fetch("https://api.resend.com/emails", {
      method:  "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization:  `Bearer ${process.env.RESEND_API_KEY}`,
      },
      body: JSON.stringify({
        from:    "Aiglos <hello@aiglos.dev>",
        to:      [email],
        subject: "Aiglos: payment issue — action needed",
        text:    "We couldn't process your last Aiglos payment. Your key has been throttled. Update your payment method at https://aiglos.dev to restore full access. Questions: hello@aiglos.dev",
      }),
    });
    console.log(`[stripe-webhook] Payment failed notice sent to ${email}`);
  } catch (err) {
    console.error("[stripe-webhook] Failed to notify customer:", err.message);
  }
}

// ── Webhook handler ───────────────────────────────────────────────────────────

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, body: "Method Not Allowed" };
  }

  const sig = event.headers["stripe-signature"];
  let stripeEvent;

  try {
    stripeEvent = stripe.webhooks.constructEvent(
      event.body,
      sig,
      process.env.AIGLOS_WEBHOOK_SECRET
    );
  } catch (err) {
    console.error("[stripe-webhook] Signature verification failed:", err.message);
    return { statusCode: 400, body: `Webhook Error: ${err.message}` };
  }

  console.log(`[stripe-webhook] Event: ${stripeEvent.type}`);

  try {
    switch (stripeEvent.type) {

      case "checkout.session.completed": {
        const session         = stripeEvent.data.object;
        const email           = session.customer_details?.email || session.metadata?.email;
        const customerId      = session.customer;
        const subscriptionId  = session.subscription;
        const sessionId       = session.id;
        if (email && subscriptionId) {
          await issueApiKey(email, customerId, subscriptionId, sessionId);
        }
        break;
      }

      case "customer.subscription.deleted": {
        const sub = stripeEvent.data.object;
        await revokeKey(sub.id);
        break;
      }

      case "invoice.payment_failed": {
        const invoice = stripeEvent.data.object;
        await throttleKey(invoice.customer);
        break;
      }

      case "invoice.payment_succeeded": {
        // Re-activate throttled key on successful retry payment
        const invoice  = stripeEvent.data.object;
        const supabase = getSupabase();
        if (supabase) {
          await supabase
            .from("api_keys")
            .update({ status: "active", updated_at: new Date().toISOString() })
            .eq("customer_id", invoice.customer)
            .eq("status", "throttled");
          console.log(`[stripe-webhook] Key re-activated for customer ${invoice.customer}`);
        }
        break;
      }

    }
  } catch (err) {
    console.error("[stripe-webhook] Handler error:", err.message);
    // Return 200 to prevent Stripe retry storm — log and investigate manually
  }

  return { statusCode: 200, body: JSON.stringify({ received: true }) };
};
