# Aiglos — Deployment Guide

## Prerequisites

- GitHub account with this repo pushed
- Netlify account (free tier)
- Stripe account
- Resend account (free tier — 3,000 emails/month)
- Supabase account (free tier — needed for automated key issuance)

---

## Step 1 — Supabase setup (~5 min)

1. [supabase.com](https://supabase.com) → New project
2. SQL Editor → New query → paste and run:

```sql
-- API keys table (issued on Stripe checkout.session.completed)
create table api_keys (
  id                  uuid primary key default gen_random_uuid(),
  api_key             text unique not null,
  customer_email      text not null,
  customer_id         text not null,
  subscription_id     text,
  checkout_session_id text unique,
  status              text not null default 'active',  -- active | revoked | throttled
  created_at          timestamptz default now(),
  updated_at          timestamptz default now()
);

create index idx_api_keys_customer_id on api_keys(customer_id);
create index idx_api_keys_subscription_id on api_keys(subscription_id);
create index idx_api_keys_checkout_session_id on api_keys(checkout_session_id);

-- Free tier signups (from modal)
create table signups (
  id         uuid primary key default gen_random_uuid(),
  email      text unique not null,
  name       text,
  plan       text default 'free',
  source     text,
  created_at timestamptz default now()
);
```

3. Settings → API → copy **Project URL** and **anon public key**

---

## Step 2 — Stripe setup (~5 min)

1. [dashboard.stripe.com](https://dashboard.stripe.com) → Products → Add product
   - Name: **Aiglos Pro**
   - Pricing: **Recurring**, $39/month, per seat
2. Payment Links → Create link → select Aiglos Pro → copy the link URL
3. Settings → Developers → API keys → copy **Publishable key** and **Secret key**
4. Developers → Webhooks → Add endpoint
   - URL: `https://YOUR-NETLIFY-DOMAIN.netlify.app/api/stripe-webhook`
   - Events: `checkout.session.completed`, `customer.subscription.deleted`,
     `invoice.payment_failed`, `invoice.payment_succeeded`
   - Copy the **Signing secret** (starts with `whsec_`)

---

## Step 3 — Resend setup (~2 min)

1. [resend.com](https://resend.com) → Create API key → copy it
2. Add a sending domain (or use the Resend test domain for early testing)

---

## Step 4 — Wire Stripe keys into index.html

Open `website/index.html`. Find near the top of the `<script>` block:

```js
const STRIPE_PAYG_PAYMENT_LINK = "STRIPE_PAYG_PAYMENT_LINK";
const STRIPE_PUBLISHABLE_KEY   = "STRIPE_PUBLISHABLE_KEY";
```

Replace with your actual values:

```js
const STRIPE_PAYG_PAYMENT_LINK = "https://buy.stripe.com/YOUR_LINK_HERE";
const STRIPE_PUBLISHABLE_KEY   = "pk_live_YOUR_KEY_HERE";
```

---

## Step 5 — Deploy on Netlify

1. Push repo to GitHub
2. [app.netlify.com](https://app.netlify.com) → Add new site → Import from GitHub
3. Select this repo
4. Build command: (leave empty)
5. Publish directory: `.`
6. Deploy

### Add environment variables in Netlify (Site settings → Environment variables):

| Variable | Value | Required |
|----------|-------|----------|
| `STRIPE_SECRET_KEY` | `sk_live_xxx` | Yes |
| `AIGLOS_WEBHOOK_SECRET` | `whsec_xxx` | Yes |
| `RESEND_API_KEY` | `re_xxx` | Yes |
| `SUPABASE_URL` | `https://xxx.supabase.co` | Yes |
| `SUPABASE_ANON_KEY` | `eyJ...` | Yes |

### Trigger a redeploy after adding env vars.

---

## Step 6 — Verify

Run through the full purchase flow end-to-end:

- [ ] Homepage loads, payment link opens Stripe Checkout
- [ ] Complete test purchase with Stripe test card `4242 4242 4242 4242`
- [ ] `checkout.session.completed` webhook fires (check Netlify function logs)
- [ ] Key appears in Supabase `api_keys` table
- [ ] Welcome email arrives with key
- [ ] `success.html?session_id=...` shows the key via `/api/get-key`
- [ ] `pip install aiglos && export AIGLOS_KEY=ak_live_xxx && python -c "import aiglos; aiglos.attach()"` works
- [ ] Free signup modal submits → email arrives
- [ ] `/scan` serves scan.html
- [ ] `/docs` redirects to GitHub

---

## All environment variables reference

See `.env.example` for the full list with descriptions.

---

## Troubleshooting

**Webhook not firing:** Check Stripe dashboard → Webhooks → event log. Common cause: Netlify domain doesn't match the webhook URL. Use the Netlify domain shown in Site settings, not a custom domain until DNS is fully propagated.

**Key not showing on success page:** `/api/get-key` returns 404 or 503. Check: (1) `get-key.js` function deployed, (2) Supabase env vars set, (3) webhook fired and wrote the key before user landed on success page. Add a retry loop — webhook can be a few seconds behind the redirect.

**Emails not sending:** Check Resend dashboard for bounces. Verify the sending domain is confirmed. For early testing, use `onboarding@resend.dev` as the from address.

**Supabase RLS:** If you enable Row Level Security on the `api_keys` table, the service role key (not anon key) is required for webhook writes. Use `SUPABASE_SERVICE_ROLE_KEY` instead of `SUPABASE_ANON_KEY` in the webhook function for production.
