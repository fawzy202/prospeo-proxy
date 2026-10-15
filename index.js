// LeadHunt API — secure version
// Every request needs a Firebase login token. Credits are charged HERE (server-side),
// so users can't edit their own balance from the browser.
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const admin = require('firebase-admin');
const Stripe = require('stripe');

const PROSPEO_KEY = process.env.PROSPEO_API_KEY;
const STRIPE_KEY = process.env.STRIPE_SECRET_KEY;
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;
const SITE_URL = (process.env.SITE_URL || '').replace(/\/+$/, ''); // e.g. https://leadhunt.ae
const stripe = STRIPE_KEY ? new Stripe(STRIPE_KEY) : null;

// Plans live HERE (the server never trusts prices sent by the browser)
const PLANS = {
  Starter:    { credits: 100,  price: 19 },
  Pro:        { credits: 200,  price: 35 },
  Business:   { credits: 2000, price: 179 },
  Enterprise: { credits: 4000, price: 299 },
};
const YEAR_DISCOUNT = 0.10;
const MIN_MONTHS_YEARLY = 6;   // yearly (discounted) plans: cancel before this many paid months = early cancellation fee of ONE month
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || 'fawzi.muhammad20@gmail.com').toLowerCase();

if (!process.env.FIREBASE_SERVICE_ACCOUNT) {
  console.error('Missing FIREBASE_SERVICE_ACCOUNT env var');
  process.exit(1);
}
admin.initializeApp({
  credential: admin.credential.cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT)),
});
const db = admin.firestore();
const FieldValue = admin.firestore.FieldValue;

const app = express();
app.set('trust proxy', true); // Render sits behind a proxy: needed to read the real client IP
app.use(cors({ origin: '*' }));

// ---------- Stripe webhook (raw body required, so it comes before express.json) ----------
app.post('/api/stripe-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!stripe || !STRIPE_WEBHOOK_SECRET) return res.status(500).send('Stripe not configured');
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], STRIPE_WEBHOOK_SECRET);
  } catch (e) {
    console.error('Webhook signature failed:', e.message);
    return res.status(400).send('Bad signature');
  }
  try {
    if (event.type === 'invoice.paid') {
      const invoice = event.data.object;

      // One-time early-cancellation fee (created by /api/cancel): only record revenue, never add credits
      if (invoice.metadata && invoice.metadata.type === 'early_cancel_fee') {
        const feeUid = invoice.metadata.uid;
        const feeAmount = (invoice.amount_paid || 0) / 100;
        const feeRef = db.collection('payments').doc(invoice.id);
        await db.runTransaction(async (t) => {
          const done = await t.get(feeRef);
          if (done.exists) return;
          t.set(feeRef, { uid: feeUid, type: 'early_cancel_fee', amount: feeAmount, at: FieldValue.serverTimestamp() });
          if (feeUid) t.set(db.collection('users').doc(feeUid), { totalPaid: FieldValue.increment(feeAmount) }, { merge: true });
        });
        return res.json({ received: true });
      }
      const subId = invoice.subscription || (invoice.parent && invoice.parent.subscription_details && invoice.parent.subscription_details.subscription);
      let meta = (invoice.parent && invoice.parent.subscription_details && invoice.parent.subscription_details.metadata) || {};
      if ((!meta.uid || !meta.plan) && subId) {
        const sub = await stripe.subscriptions.retrieve(typeof subId === 'string' ? subId : subId.id);
        meta = sub.metadata || {};
      }
      const uid = meta.uid;
      const plan = PLANS[meta.plan];
      if (!uid || !plan) { console.error('invoice.paid without usable metadata', invoice.id); return res.json({ received: true }); }
      const credits = plan.credits;   // every paid month (monthly or yearly-commitment) grants the plan's monthly credits
      const amount = (invoice.amount_paid || 0) / 100;

      // idempotent: a paid invoice is only credited once
      const payRef = db.collection('payments').doc(invoice.id);
      await db.runTransaction(async (t) => {
        const done = await t.get(payRef);
        if (done.exists) return;
        t.set(payRef, { uid, plan: meta.plan, billing: meta.billing || 'monthly', credits, amount, email: invoice.customer_email || null, at: FieldValue.serverTimestamp() });
        const userUpdate = {
          credits: FieldValue.increment(credits),
          totalPaid: FieldValue.increment(amount),
          stripeCustomerId: invoice.customer || null,
          plan: meta.plan,
          billing: meta.billing || 'monthly',
        };
        userUpdate.paidMonths = invoice.billing_reason === 'subscription_create' ? 1 : FieldValue.increment(1);
        userUpdate.cancelAtPeriodEnd = false;
        if (subId) userUpdate.stripeSubscriptionId = typeof subId === 'string' ? subId : subId.id;
        t.set(db.collection('users').doc(uid), userUpdate, { merge: true });
      });
    }
    res.json({ received: true });
  } catch (e) {
    console.error('Webhook handler error:', e);
    res.status(500).send('Handler error'); // Stripe will retry
  }
});

app.use(express.json({ limit: '100kb' }));

// ---------- helpers ----------
const fail = (res, status, code, message) => res.status(status).json({ error: true, code, message });

// Login check
async function requireAuth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return fail(res, 401, 'UNAUTHENTICATED', 'Please log in first.');
  try {
    req.user = await admin.auth().verifyIdToken(token);
  } catch (e) {
    return fail(res, 401, 'UNAUTHENTICATED', 'Session expired. Please log in again.');
  }
  next();
}

// Must have a verified email (stops fake-account farming)
function requireVerified(req, res, next) {
  if (!req.user.email_verified) {
    return fail(res, 403, 'EMAIL_NOT_VERIFIED', 'Please verify your email first.');
  }
  next();
}

function requireAdmin(req, res, next) {
  const email = (req.user.email || '').toLowerCase();
  if (!req.user.email_verified || email !== ADMIN_EMAIL) {
    return fail(res, 403, 'FORBIDDEN', 'Admins only.');
  }
  next();
}

// Simple per-user rate limit: 60 requests / minute
const hits = new Map();
function rateLimit(req, res, next) {
  const key = req.user.uid;
  const now = Date.now();
  const arr = (hits.get(key) || []).filter((t) => now - t < 60000);
  if (arr.length >= 60) return fail(res, 429, 'RATE_LIMIT', 'Too many requests. Slow down a bit.');
  arr.push(now);
  hits.set(key, arr);
  next();
}
setInterval(() => { const now = Date.now(); for (const [k, v] of hits) if (!v.some((t) => now - t < 60000)) hits.delete(k); }, 120000).unref();

// Take credits up-front (atomic). Throws NO_CREDITS if balance is too low.
async function reserve(uid, cost) {
  const ref = db.collection('users').doc(uid);
  await db.runTransaction(async (t) => {
    const snap = await t.get(ref);
    const credits = snap.exists ? Number(snap.data().credits) || 0 : 0;
    if (credits < cost) {
      const err = new Error('Not enough credits');
      err.code = 'NO_CREDITS';
      throw err;
    }
    t.update(ref, { credits: FieldValue.increment(-cost) });
  });
}
async function refund(uid, amount) {
  if (amount > 0) await db.collection('users').doc(uid).update({ credits: FieldValue.increment(amount) });
}

async function prospeo(path, body) {
  const r = await fetch('https://api.prospeo.io/' + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-KEY': PROSPEO_KEY },
    body: JSON.stringify(body),
  });
  return r.json();
}

const handleErr = (res, e) => {
  if (e.code === 'NO_CREDITS') return fail(res, 402, 'NO_CREDITS', 'Not enough credits. Please top up.');
  console.error(e);
  return fail(res, 500, 'SERVER_ERROR', e.message || 'Server error');
};


// Prospeo returns FULL emails/phones for people already revealed on OUR Prospeo account
// (e.g. from our own tests). Hide them so users must pay a credit to reveal.
function maskEmail(e) {
  const [l, d] = String(e).split('@');
  return (l ? l[0] : '') + '*****' + (d ? '@' + d : '');
}
function maskPhone(ph) {
  const s = String(ph);
  return s.length > 4 ? s.slice(0, 4) + '*'.repeat(Math.max(s.length - 4, 4)) : '****';
}
function maskResults(d) {
  if (!d || !Array.isArray(d.results)) return d;
  d.results.forEach((r) => {
    const p = r && r.person;
    if (!p) return;
    if (p.email && p.email.email && !String(p.email.email).includes('*')) p.email.email = maskEmail(p.email.email);
    if (p.mobile && p.mobile.mobile && !String(p.mobile.mobile).includes('*')) p.mobile.mobile = maskPhone(p.mobile.mobile);
  });
  return d;
}


// Contacts a user already revealed are saved at users/{uid}/revealed/{person_id} (server-only access).
const revealedRef = (uid, personId) =>
  db.collection('users').doc(uid).collection('revealed').doc(String(personId).replace(/\//g, '_'));

async function applyRevealed(uid, d) {
  if (!d || !Array.isArray(d.results) || !d.results.length) return d;
  const withId = d.results.filter((r) => r && r.person && r.person.person_id);
  if (!withId.length) return d;
  const snaps = await db.getAll(...withId.map((r) => revealedRef(uid, r.person.person_id)));
  snaps.forEach((snap, i) => {
    if (!snap.exists) return;
    const saved = snap.data();
    const p = withId[i].person;
    if (saved.email && saved.email.email) p.email = saved.email;
    if (saved.mobile && saved.mobile.mobile) p.mobile = saved.mobile;
  });
  return d;
}

// ---------- routes ----------
app.get('/', (req, res) => res.json({ status: 'LeadHunt API running' }));


// ---------- free trial (anti-abuse) ----------
const FREE_CREDITS = 10;
const MAX_TRIALS_PER_IP = 2;          // per IP, per 30 days
const IP_WINDOW_MS = 30 * 24 * 3600 * 1000;
const DISPOSABLE = new Set(['mailinator.com','10minutemail.com','guerrillamail.com','guerrillamail.net','tempmail.com','temp-mail.org','temp-mail.io','yopmail.com','trashmail.com','throwaway.email','sharklasers.com','getnada.com','dispostable.com','maildrop.cc','fakeinbox.com','mintemail.com','mohmal.com','emailondeck.com','tempail.com','moakt.com','burnermail.io','spamgourmet.com','mailnesia.com','tempinbox.com','mytemp.email','inboxkitten.com','33mail.com']);
const sha = (v) => crypto.createHash('sha256').update(v).digest('hex');
function normEmail(email) {
  let [local, domain] = String(email).toLowerCase().trim().split('@');
  if (!domain) return String(email).toLowerCase();
  if (domain === 'googlemail.com') domain = 'gmail.com';
  local = local.split('+')[0];                       // name+anything@ -> name@
  if (domain === 'gmail.com') local = local.replace(/\./g, ''); // g.m.a.i.l dots don't matter
  return local + '@' + domain;
}

// Called once after login. Creates the user doc and decides whether the free trial is granted.
app.post('/api/init', requireAuth, requireVerified, rateLimit, async (req, res) => {
  try {
    const uid = req.user.uid;
    const email = req.user.email || '';
    const domain = email.split('@')[1] || '';
    const name = String((req.body && req.body.name) || req.user.name || email.split('@')[0]).slice(0, 60);
    const emailHash = sha(normEmail(email));
    const ipHash = sha(req.ip || 'unknown');
    const userRef = db.collection('users').doc(uid);
    const emailRef = db.collection('freeClaims').doc(emailHash);
    const ipRef = db.collection('ipClaims').doc(ipHash);

    const result = await db.runTransaction(async (t) => {
      const [u, e, ip] = await Promise.all([t.get(userRef), t.get(emailRef), t.get(ipRef)]);
      if (u.exists) return { credits: Number(u.data().credits) || 0, trial: 'existing' };

      let reason = null;
      if (DISPOSABLE.has(domain)) reason = 'disposable_email';
      else if (e.exists) reason = 'email_already_used';
      else if (ip.exists) {
        const d = ip.data();
        if (Date.now() - (d.first || 0) < IP_WINDOW_MS && (d.count || 0) >= MAX_TRIALS_PER_IP) reason = 'ip_limit';
      }
      const granted = !reason;
      t.set(userRef, {
        email, name,
        credits: granted ? FREE_CREDITS : 0,
        trialGranted: granted,
        trialDeniedReason: reason,
        createdAt: FieldValue.serverTimestamp(),
      });
      if (granted) {
        t.set(emailRef, { uid, at: FieldValue.serverTimestamp() });
        const d = ip.exists ? ip.data() : null;
        const fresh = !d || Date.now() - (d.first || 0) >= IP_WINDOW_MS;
        t.set(ipRef, { first: fresh ? Date.now() : d.first, count: fresh ? 1 : (d.count || 0) + 1 });
      }
      return { credits: granted ? FREE_CREDITS : 0, trial: granted ? 'granted' : 'denied', reason };
    });
    res.json(result);
  } catch (e) { handleErr(res, e); }
});

// Search: 1 credit per page, only charged if results come back
app.post('/api/search', requireAuth, requireVerified, rateLimit, async (req, res) => {
  const uid = req.user.uid;
  let reserved = false;
  try {
    const page = Math.min(Math.max(parseInt(req.body.page, 10) || 1, 1), 1000);
    const filters = req.body.filters && typeof req.body.filters === 'object' ? req.body.filters : {};
    await reserve(uid, 1);
    reserved = true;
    const d = await prospeo('search-person', { page, filters });
    const ok = !d.error && Array.isArray(d.results) && d.results.length > 0;
    if (!ok) { await refund(uid, 1); reserved = false; return res.json(d); }
    d._charged = 1;
    maskResults(d);
    await applyRevealed(uid, d);   // contacts THIS user already paid for stay visible
    res.json(d);
  } catch (e) {
    if (reserved) await refund(uid, 1).catch(() => {});
    handleErr(res, e);
  }
});

// Reveal: email 1 credit, phone 10 credits — each charged only if actually found.
// Anything this user already revealed before is free to see again.
app.post('/api/enrich', requireAuth, requireVerified, rateLimit, async (req, res) => {
  const uid = req.user.uid;
  let reservedAmount = 0;
  try {
    const mode = ['email', 'phone', 'both'].includes(req.body.mode) ? req.body.mode : 'email';
    const personId = req.body.person_id;
    if (!personId || typeof personId !== 'string') return fail(res, 400, 'BAD_REQUEST', 'person_id required');
    const wantEmail = mode !== 'phone';
    const wantPhone = mode !== 'email';

    const ref = revealedRef(uid, personId);
    const savedSnap = await ref.get();
    const saved = savedSnap.exists ? savedSnap.data() : {};
    const haveEmail = !!(saved.email && saved.email.email);
    const havePhone = !!(saved.mobile && saved.mobile.mobile);
    const needEmail = wantEmail && !haveEmail;
    const needPhone = wantPhone && !havePhone;

    // Already revealed by this user: show it again, no charge, no Prospeo call
    if (!needEmail && !needPhone) {
      return res.json({ error: false, response: { person: { email: saved.email, mobile: saved.mobile } }, _charged: 0, _cached: true });
    }

    const maxCost = (needEmail ? 1 : 0) + (needPhone ? 10 : 0);
    await reserve(uid, maxCost);
    reservedAmount = maxCost;

    const d = await prospeo('enrich-person', {
      data: { person_id: personId },
      only_verified_email: false,
      enrich_mobile: needPhone,
      skip_email: !needEmail,
    });
    const p = (d.response && d.response.person) || d.person || {};
    const gotEmail = !!(p.email && p.email.email);
    const gotPhone = !!(p.mobile && p.mobile.mobile);
    const charge = (needEmail && gotEmail ? 1 : 0) + (needPhone && gotPhone ? 10 : 0);
    await refund(uid, maxCost - charge);
    reservedAmount = 0;

    // remember what this user paid for
    const toSave = {};
    if (needEmail && gotEmail) toSave.email = p.email;
    if (needPhone && gotPhone) toSave.mobile = p.mobile;
    if (Object.keys(toSave).length) {
      toSave.updatedAt = FieldValue.serverTimestamp();
      await ref.set(toSave, { merge: true });
    }

    // answer with everything this user now has for this person
    const merged = Object.assign({}, p);
    if (!gotEmail && haveEmail) merged.email = saved.email;
    if (!gotPhone && havePhone) merged.mobile = saved.mobile;
    if (d.response) d.response.person = merged; else d.person = merged;
    d._charged = charge;
    res.json(d);
  } catch (e) {
    if (reservedAmount) await refund(uid, reservedAmount).catch(() => {});
    handleErr(res, e);
  }
});

// Autocomplete suggestions: free, but login required
app.post('/api/suggestions', requireAuth, rateLimit, async (req, res) => {
  try {
    const b = req.body || {};
    const body = {};
    if (b.location_search) body.location_search = String(b.location_search).slice(0, 100);
    if (b.job_title_search) body.job_title_search = String(b.job_title_search).slice(0, 100);
    res.json(await prospeo('search-suggestions', body));
  } catch (e) { handleErr(res, e); }
});


// ---------- payments ----------
// Start a Stripe Checkout (subscription). Plan + price are decided here, not by the browser.
app.post('/api/checkout', requireAuth, requireVerified, rateLimit, async (req, res) => {
  try {
    if (!stripe || !SITE_URL) return fail(res, 503, 'PAYMENTS_OFF', 'Payments are not configured yet.');
    const planId = req.body && req.body.plan;
    const billing = req.body && req.body.billing === 'yearly' ? 'yearly' : 'monthly';
    const plan = PLANS[planId];
    if (!plan) return fail(res, 400, 'BAD_PLAN', 'Unknown plan');
    // yearly plan = billed MONTHLY at the discounted price
    const cents = billing === 'yearly' ? Math.round(plan.price * (1 - YEAR_DISCOUNT) * 100) : plan.price * 100;
    const meta = { uid: req.user.uid, plan: planId, billing };
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      customer_email: req.user.email,
      client_reference_id: req.user.uid,
      line_items: [{
        quantity: 1,
        price_data: {
          currency: 'usd',
          unit_amount: cents,
          recurring: { interval: 'month' },
          product_data: {
            name: 'LeadHunt ' + planId + (billing === 'yearly' ? ' (billed monthly, 10% off)' : ' (Monthly)'),
            description: plan.credits + ' credits / month',
          },
        },
      }],
      metadata: meta,
      subscription_data: { metadata: meta },
      success_url: SITE_URL + '/?paid=1',
      cancel_url: SITE_URL + '/?canceled=1',
    });
    res.json({ url: session.url });
  } catch (e) { handleErr(res, e); }
});

// Stripe's hosted page: change card / see invoices / cancel.
// Cancel works for everyone: it ends the plan at the END of the month already paid (no refund for the current month).
const portalCache = {};
async function portalConfigId(committed) {
  const key = committed ? 'committed' : 'standard';
  if (portalCache[key]) return portalCache[key];
  const list = await stripe.billingPortal.configurations.list({ limit: 100, is_active: true });
  let found = list.data.find((c) => c.metadata && c.metadata.leadhunt === key);
  if (!found) {
    found = await stripe.billingPortal.configurations.create({
      business_profile: { headline: 'LeadHunt subscription' },
      features: {
        invoice_history: { enabled: true },
        payment_method_update: { enabled: true },
        customer_update: { enabled: true, allowed_updates: ['email', 'name', 'address'] },
        subscription_cancel: committed ? { enabled: false } : { enabled: true, mode: 'at_period_end' },
      },
      metadata: { leadhunt: key },
    });
  }
  portalCache[key] = found.id;
  return found.id;
}

app.post('/api/portal', requireAuth, requireVerified, rateLimit, async (req, res) => {
  try {
    if (!stripe || !SITE_URL) return fail(res, 503, 'PAYMENTS_OFF', 'Payments are not configured yet.');
    const snap = await db.collection('users').doc(req.user.uid).get();
    const u = snap.exists ? snap.data() : {};
    if (!u.stripeCustomerId) return fail(res, 404, 'NO_SUBSCRIPTION', 'No active subscription found.');
    const committed = true; // portal = card + invoices only. Cancelling goes through /api/cancel (it may need an early-cancellation fee)
    const session = await stripe.billingPortal.sessions.create({
      customer: u.stripeCustomerId,
      return_url: SITE_URL,
      configuration: await portalConfigId(committed),
    });
    res.json({ url: session.url, committed });
  } catch (e) { handleErr(res, e); }
});

// ---------- cancellation ----------
// Monthly plan: cancel anytime. Yearly (discounted) plan: if cancelled before MIN_MONTHS_YEARLY paid months,
// a one-time fee of ONE month is charged. In every case the plan stays active until the end of the month already paid.
function cancelQuote(u) {
  const plan = PLANS[u.plan];
  const paidMonths = Number(u.paidMonths) || 0;
  const yearly = u.billing === 'yearly';
  const early = yearly && paidMonths < MIN_MONTHS_YEARLY;
  const feeCents = early && plan ? Math.round(plan.price * (1 - YEAR_DISCOUNT) * 100) : 0;
  return { plan: u.plan || null, billing: u.billing || 'monthly', paidMonths, minMonths: MIN_MONTHS_YEARLY, feeCents, fee: feeCents / 100 };
}

app.post('/api/cancel-info', requireAuth, requireVerified, rateLimit, async (req, res) => {
  try {
    const snap = await db.collection('users').doc(req.user.uid).get();
    const u = snap.exists ? snap.data() : {};
    if (!u.stripeSubscriptionId) return fail(res, 404, 'NO_SUBSCRIPTION', 'No active subscription found.');
    if (u.cancelAtPeriodEnd) return fail(res, 409, 'ALREADY_CANCELED', 'Your subscription is already set to end.');
    res.json(cancelQuote(u));
  } catch (e) { handleErr(res, e); }
});

app.post('/api/cancel', requireAuth, requireVerified, rateLimit, async (req, res) => {
  try {
    if (!stripe) return fail(res, 503, 'PAYMENTS_OFF', 'Payments are not configured yet.');
    const userRef = db.collection('users').doc(req.user.uid);
    const snap = await userRef.get();
    const u = snap.exists ? snap.data() : {};
    if (!u.stripeSubscriptionId || !u.stripeCustomerId) return fail(res, 404, 'NO_SUBSCRIPTION', 'No active subscription found.');
    if (u.cancelAtPeriodEnd) return fail(res, 409, 'ALREADY_CANCELED', 'Your subscription is already set to end.');

    const quote = cancelQuote(u);
    const sub = await stripe.subscriptions.retrieve(u.stripeSubscriptionId);
    if (sub.status === 'canceled') return fail(res, 409, 'ALREADY_CANCELED', 'Subscription already ended.');

    // 1) early-cancellation fee (charged first; if the card fails, nothing is cancelled)
    if (quote.feeCents > 0) {
      await stripe.invoiceItems.create({
        customer: u.stripeCustomerId,
        amount: quote.feeCents,
        currency: 'usd',
        description: 'Early cancellation fee (yearly plan cancelled before ' + MIN_MONTHS_YEARLY + ' months)',
      });
      let invoice = await stripe.invoices.create({
        customer: u.stripeCustomerId,
        collection_method: 'charge_automatically',
        auto_advance: false,
        pending_invoice_items_behavior: 'include',
        default_payment_method: typeof sub.default_payment_method === 'string' ? sub.default_payment_method : (sub.default_payment_method && sub.default_payment_method.id) || undefined,
        metadata: { type: 'early_cancel_fee', uid: req.user.uid },
      });
      try {
        invoice = await stripe.invoices.finalizeInvoice(invoice.id);
        await stripe.invoices.pay(invoice.id);
      } catch (payErr) {
        await stripe.invoices.voidInvoice(invoice.id).catch(() => {});
        return fail(res, 402, 'FEE_PAYMENT_FAILED', 'Could not charge the early cancellation fee. Please update your card and try again.');
      }
    }

    // 2) end the plan after the month that is already paid
    const updated = await stripe.subscriptions.update(u.stripeSubscriptionId, { cancel_at_period_end: true });
    await userRef.set({
      cancelAtPeriodEnd: true,
      cancelEffective: updated.cancel_at ? admin.firestore.Timestamp.fromMillis(updated.cancel_at * 1000) : null,
    }, { merge: true });
    res.json({ ok: true, fee: quote.fee, endsAt: updated.cancel_at ? updated.cancel_at * 1000 : null });
  } catch (e) { handleErr(res, e); }
});

// Prospeo account info: admin only
app.get('/api/account', requireAuth, requireAdmin, async (req, res) => {
  try {
    const r = await fetch('https://api.prospeo.io/account-information', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-KEY': PROSPEO_KEY },
    });
    res.json(await r.json());
  } catch (e) { handleErr(res, e); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('LeadHunt API on port ' + PORT));
