require('dotenv').config();
const express = require('express');
const cors = require('cors');
const twilio = require('twilio');
const admin = require('firebase-admin');
const fs = require('fs');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

console.log('Server time:', new Date().toISOString());

function bad(msg) {
  console.error(msg);
}

// Load Firebase credentials
function initFirebase() {
  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    try {
      const svc = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
      admin.initializeApp({ credential: admin.credential.cert(svc) });
      return true;
    } catch (e) {
      bad('Invalid FIREBASE_SERVICE_ACCOUNT: ' + e.message);
      return false;
    }
  }
  if (process.env.SERVICE_ACCOUNT_PATH) {
    try {
      const svc = require(process.env.SERVICE_ACCOUNT_PATH);
      admin.initializeApp({ credential: admin.credential.cert(svc) });
      return true;
    } catch (e) {
      bad('Failed loading service account from path: ' + e.message);
      return false;
    }
  }
  if (process.env.GOOGLE_APPLICATION_CREDENTIALS) {
    admin.initializeApp();
    return true;
  }
  bad('No Firebase credential configured. Set FIREBASE_SERVICE_ACCOUNT or SERVICE_ACCOUNT_PATH or GOOGLE_APPLICATION_CREDENTIALS.');
  return false;
}

if (!initFirebase()) process.exit(1);

const twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

// In-memory stores (demo only)
const otps = new Map();
const rate = new Map();
const OTP_WINDOW_MS = parseInt(process.env.OTP_WINDOW_MS || '3600000', 10);
const OTP_MAX_PER_WINDOW = parseInt(process.env.OTP_MAX_PER_WINDOW || '5', 10);

function genOtp() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function normalizePhone(p) {
  // Expect full E.164 like +964770...
  return p.replace(/\s+/g, '');
}

app.post('/send-otp', async (req, res) => {
  const phoneRaw = req.body && req.body.phone;
  if (!phoneRaw) return res.status(400).json({ error: 'phone required' });
  const phone = normalizePhone(phoneRaw);

  // rate limiting
  const now = Date.now();
  let st = rate.get(phone);
  if (!st || now - st.firstTs > OTP_WINDOW_MS) {
    st = { count: 0, firstTs: now };
    rate.set(phone, st);
  }
  if (st.count >= OTP_MAX_PER_WINDOW) return res.status(429).json({ error: 'Rate limit exceeded' });
  st.count++;

  const otp = genOtp();
  const expiresAt = now + (parseInt(process.env.OTP_EXPIRY_SECONDS || '300', 10) * 1000);

  // send SMS only
  let channel = 'sms';
  try {
    const smsFrom = process.env.TWILIO_SMS_FROM;
    if (!smsFrom) {
      bad('TWILIO_SMS_FROM not configured');
      return res.status(500).json({ error: 'SMS sender not configured' });
    }
    const m = await twilioClient.messages.create({ from: smsFrom, to: phone, body: `رمز التحقق: ${otp}` });
    console.log('SMS sid', m.sid);
  } catch (e) {
    bad('SMS send failed: ' + (e && e.message));
    return res.status(500).json({ error: 'Failed to send OTP' });
  }

  otps.set(phone, { otp, expiresAt, channel });
  return res.json({ success: true, channel });
});

app.post('/verify-otp', async (req, res) => {
  const { phone: phoneRaw, otp } = req.body || {};
  if (!phoneRaw || !otp) return res.status(400).json({ error: 'phone and otp required' });
  const phone = normalizePhone(phoneRaw);
  const entry = otps.get(phone);
  if (!entry) return res.status(400).json({ error: 'No OTP sent' });
  if (Date.now() > entry.expiresAt) {
    otps.delete(phone);
    return res.status(400).json({ error: 'OTP expired' });
  }
  if (entry.otp !== String(otp)) return res.status(400).json({ error: 'Invalid OTP' });

  try {
    const uid = `sms:${phone}`;
    try { await admin.auth().getUser(uid); } catch (_) {
      try { await admin.auth().createUser({ uid, phoneNumber: phone }); } catch (e) { bad('createUser failed: '+e.message); }
    }
    // store minimal profile in Firestore
    try {
      const db = admin.firestore();
      await db.collection('users').doc(uid).set({ phone, provider: 'sms', updatedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
    } catch (e) { bad('firestore write failed: '+(e && e.message)); }

    const token = await admin.auth().createCustomToken(uid, { provider: 'sms' });
    otps.delete(phone);
    return res.json({ success: true, token });
  } catch (e) {
    bad('verify error: ' + (e && e.message));
    return res.status(500).json({ error: 'Failed to verify' });
  }
});

app.get('/', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));

const srv = app.listen(PORT, () => console.log(`Server listening on ${PORT}`));

process.on('SIGTERM', () => { console.warn('SIGTERM'); srv.close(() => process.exit(0)); });
process.on('SIGINT', () => { console.warn('SIGINT'); process.exit(0); });
process.on('unhandledRejection', (r,p) => bad('unhandledRejection '+(r&&r.message))); 
process.on('uncaughtException', (err) => { bad('uncaughtException '+(err&&err.message)); process.exit(1); });
