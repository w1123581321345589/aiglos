# aiglos.dev — Deploy in 10 Minutes

Everything you need to go from this repo to live signups with Stripe in under 10 minutes.

---

## What's in the box

```
index.html                          Landing page + signup modal
success.html                        Post-checkout API key delivery page
netlify.toml                        Routing + security headers
netlify/functions/
  signup.js                         Free tier signup (email capture)
  create-checkout-session.js        Stripe Checkout session creation
  stripe-webhook.js                 Stripe event handler + API key issuance
```

---

## Step 1 — Stripe setup (5 minutes)

### Create your products

1. Go to [dashboard.stripe.com/products](https://dashboard.stripe.com/products)
2. Create a product: **Aiglos Pay-as-you-go**
3. Add a recurring price: **$0.001 per unit** (usage-based, metered)
   - Billing scheme: Per unit
   - Usage type: Metered
   - Aggregation: Sum
4. Copy the **Price ID** (looks like `price_1ABC...`) — you need this in Step 3.

### Option A — Payment Link (fastest, no backend needed)

1. Products → your Aiglos product → Create payment link
2. Copy the payment link URL (looks like `https://buy.stripe.com/abc123`)
3. Paste it into `index.html` at the `STRIPE_PAYG_PAYMENT_LINK` constant.
4. That's it. No backend needed. Customers go to Stripe's hosted page.

### Option B — Stripe Checkout (backend required, more control)

Continue to Step 2 for the full flow.

---

## Step 2 — Deploy to Netlify (2 minutes)

### Via Netlify CLI (fastest)

```bash
npm install -g netlify-cli
cd aiglos-site
netlify init         # connect to your Netlify account
netlify deploy --prod
```

### Via GitHub

1. Push this folder to a GitHub repo
2. Go to [app.netlify.com](https://app.netlify.com) → New site from Git
3. Connect your repo
4. Build settings: leave blank (static site)
5. Deploy

Your site is live at `https://your-site.netlify.app`. Add your custom domain in Netlify → Domain settings.

---

## Step 3 — Environment variables

In Netlify dashboard → Site settings → Environment variables, add:

| Variable | Value |
|---|---|
| `STRIPE_SECRET_KEY` | `sk_live_xxx` (from Stripe dashboard → API keys) |
| `STRIPE_PAYG_PRICE_ID` | `price_xxx` (from Step 1) |
| `AIGLOS_WEBHOOK_SECRET` | `whsec_xxx` (from Step 4) |
| `SITE_URL` | `https://aiglos.dev` |
| `RESEND_API_KEY` | Your Resend/Postmark/SendGrid key (for emails) |

---

## Step 4 — Stripe webhook (1 minute)

1. Stripe dashboard → Developers → Webhooks → Add endpoint
2. URL: `https://aiglos.dev/api/stripe-webhook`
3. Events to listen for:
   - `checkout.session.completed`
   - `customer.subscription.deleted`
   - `invoice.payment_failed`
4. Copy the **Signing secret** (`whsec_xxx`) → paste into Netlify env vars as `AIGLOS_WEBHOOK_SECRET`

---

## Step 5 — Update index.html constants

In `index.html`, find the CONFIG block near the bottom and update:

```javascript
const STRIPE_PUBLISHABLE_KEY = 'pk_live_REPLACE_WITH_YOUR_STRIPE_KEY';
const STRIPE_PAYG_PAYMENT_LINK = 'https://buy.stripe.com/REPLACE_WITH_PAYMENT_LINK';
```

Get your publishable key from Stripe dashboard → Developers → API keys.

---

## Step 6 — Wire up email delivery

In `netlify/functions/stripe-webhook.js`, the `sendWelcomeEmail()` function is scaffolded but needs your email provider connected.

Fastest option — [Resend](https://resend.com) (free tier, great deliverability):

```bash
npm install resend
```

Then in `stripe-webhook.js`, uncomment the Resend block and set `RESEND_API_KEY` in Netlify env vars.

---

## Step 7 — Wire up API key storage

In `netlify/functions/stripe-webhook.js`, the `issueApiKey()` function generates keys but needs a place to store them.

Fastest option — [Supabase](https://supabase.com) (free tier):

1. Create a Supabase project
2. Create table: `api_keys` with columns: `key`, `customer_email`, `customer_id`, `subscription_id`, `created_at`, `status`
3. Set `SUPABASE_URL` and `SUPABASE_ANON_KEY` in Netlify env vars
4. Uncomment the Supabase block in `issueApiKey()`

---

## That's it

Timeline:
- Payment Link path (no backend): **5 minutes**
- Full Checkout + webhook + email: **10 minutes**
- Add key storage: **15 minutes**

The free tier signup already works with just the HTML — no backend needed for that path.

---

## Local development

```bash
npm install -g netlify-cli
npm install stripe   # for functions
netlify dev          # runs site + functions on localhost:8888
```

Test Stripe webhooks locally:

```bash
stripe listen --forward-to localhost:8888/api/stripe-webhook
```

---

## Pricing notes

The Stripe product you create is for the **subscription** that enables cloud telemetry access. The actual per-call billing happens when your Aiglos backend reports usage to Stripe's Metered Billing API via:

```javascript
await stripe.subscriptionItems.createUsageRecord(subscriptionItemId, {
  quantity: callCount,
  timestamp: Math.floor(Date.now() / 1000),
  action: 'increment',
});
```

This gets called from your Aiglos cloud API when it receives metered events from customer instances.
