// LeadHunt API — secure version
// Every request needs a Firebase login token. Credits are charged HERE (server-side),
// so users can't edit their own balance from the browser.
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const admin = require('firebase-admin');

const PROSPEO_KEY = process.env.PROSPEO_API_KEY;
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
    res.json(d);
  } catch (e) {
    if (reserved) await refund(uid, 1).catch(() => {});
    handleErr(res, e);
  }
});

// Reveal: email 1 credit, phone 10 credits — each charged only if actually found
app.post('/api/enrich', requireAuth, requireVerified, rateLimit, async (req, res) => {
  const uid = req.user.uid;
  let reservedAmount = 0;
  try {
    const mode = ['email', 'phone', 'both'].includes(req.body.mode) ? req.body.mode : 'email';
    const personId = req.body.person_id;
    if (!personId || typeof personId !== 'string') return fail(res, 400, 'BAD_REQUEST', 'person_id required');
    const wantEmail = mode !== 'phone';
    const wantPhone = mode !== 'email';
    const maxCost = (wantEmail ? 1 : 0) + (wantPhone ? 10 : 0);

    await reserve(uid, maxCost);
    reservedAmount = maxCost;

    const d = await prospeo('enrich-person', {
      data: { person_id: personId },
      only_verified_email: false,
      enrich_mobile: wantPhone,
      skip_email: !wantEmail,
    });
    const p = (d.response && d.response.person) || d.person || {};
    const gotEmail = !!(p.email && p.email.email);
    const gotPhone = !!(p.mobile && p.mobile.mobile);
    const charge = (wantEmail && gotEmail ? 1 : 0) + (wantPhone && gotPhone ? 10 : 0);
    await refund(uid, maxCost - charge);
    reservedAmount = 0;
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
