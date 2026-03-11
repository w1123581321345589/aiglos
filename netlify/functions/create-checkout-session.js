// netlify/functions/create-checkout-session.js
// Handles POST /api/create-checkout-session
//
// Deploy on Netlify (free tier is fine for this usage).
// Set these env vars in the Netlify dashboard:
//   STRIPE_SECRET_KEY      = sk_live_xxx
//   STRIPE_PAYG_PRICE_ID   = price_xxx  (metered usage price)
//   AIGLOS_WEBHOOK_SECRET  = whsec_xxx  (from Stripe webhook dashboard)
//   SITE_URL               = https://aiglos.dev

const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  const headers = {
    'Access-Control-Allow-Origin': process.env.SITE_URL || '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Content-Type': 'application/json',
  };

  try {
    const { email, name, priceId } = JSON.parse(event.body || '{}');

    if (!email) {
      return { statusCode: 400, headers, body: JSON.stringify({ error: 'Email required' }) };
    }

    const price = priceId || process.env.STRIPE_PAYG_PRICE_ID;

    // Create or retrieve customer
    let customer;
    const existing = await stripe.customers.list({ email, limit: 1 });
    if (existing.data.length > 0) {
      customer = existing.data[0];
    } else {
      customer = await stripe.customers.create({ email, name });
    }

    // Create Checkout session (subscription for usage-based billing)
    const session = await stripe.checkout.sessions.create({
      customer: customer.id,
      payment_method_types: ['card'],
      mode: 'subscription',
      line_items: [{ price, quantity: 1 }],
      success_url: `${process.env.SITE_URL || 'https://aiglos.dev'}/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url:  `${process.env.SITE_URL || 'https://aiglos.dev'}/?canceled=1`,
      subscription_data: {
        metadata: { source: 'aiglos.dev', plan: 'payg' }
      },
      metadata: { email, name },
      allow_promotion_codes: true,
    });

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ sessionId: session.id }),
    };
  } catch (err) {
    console.error('[Aiglos] Checkout session error:', err.message);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: err.message }),
    };
  }
};
