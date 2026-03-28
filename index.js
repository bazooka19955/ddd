require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const twilio = require('twilio');
const admin = require('firebase-admin');
const fs = require('fs');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// IMPORTANT: When deploying online (Railway, Render, etc),
// set SERVER_BASE_URL in your .env or Railway Variables to your public server URL, e.g.:
// SERVER_BASE_URL=https://ddd-production-9afe.up.railway.app
// Do NOT use localhost in production!
const PORT = process.env.PORT || 3000;

// print server time to help diagnose clock skew issues
console.log('Server time:', new Date().toISOString());

// Initialize Firebase Admin with basic validation and helpful error messages
if (process.env.FIREBASE_SERVICE_ACCOUNT) {
  try {
    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    // basic validation of private_key format
    if (!serviceAccount.private_key || !serviceAccount.private_key.includes('PRIVATE KEY')) {
      console.warn('Firebase service account seems invalid: missing or malformed private_key.');
    }
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
    });
  } catch (err) {
    console.error('Failed parsing FIREBASE_SERVICE_ACCOUNT:', err.message);
    process.exit(1);
  }
} else if (process.env.SERVICE_ACCOUNT_PATH) {
  try {
    const serviceAccount = require(process.env.SERVICE_ACCOUNT_PATH);
    if (!serviceAccount.private_key || !serviceAccount.private_key.includes('PRIVATE KEY')) {
      console.warn('Firebase service account file seems invalid: missing or malformed private_key.');
    }
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
    });
  } catch (err) {
    console.error('Failed loading service account from path:', err.message);
    process.exit(1);
  }
} else if (process.env.GOOGLE_APPLICATION_CREDENTIALS) {
  // Rely on GOOGLE_APPLICATION_CREDENTIALS environment and ADC
  admin.initializeApp();
} else {
  console.error('No Firebase service account configured. Set FIREBASE_SERVICE_ACCOUNT, SERVICE_ACCOUNT_PATH or GOOGLE_APPLICATION_CREDENTIALS.');
  process.exit(1);
}

const twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

// Simple in-memory store for OTPs (for demo). Replace with DB in production.
const otps = new Map();

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

app.post('/send-otp', async (req, res) => {
  const { phone } = req.body;
  if (!phone) return res.status(400).json({ error: 'phone required' });
  const otp = generateOTP();
  const expiresAt = Date.now() + (parseInt(process.env.OTP_EXPIRY_SECONDS || '300') * 1000);
  try {
    // send via Twilio WhatsApp (body only, no contentSid/contentVariables)
    await twilioClient.messages.create({
      from: process.env.TWILIO_WHATSAPP_FROM,
      to: `whatsapp:${phone}`,
      body: `رمز التحقق الخاص بك هو: ${otp}`
    });
    otps.set(phone, { otp, expiresAt });
    return res.json({ success: true });
  } catch (e) {
    console.error('Twilio error:', e);
    return res.status(500).json({
      error: 'Failed to send OTP',
      details: e.message,
      twilio: e
    });
  }
});

app.post('/verify-otp', async (req, res) => {
  const { phone, otp } = req.body;
  if (!phone || !otp) return res.status(400).json({ error: 'phone and otp required' });
  const entry = otps.get(phone);
  if (!entry) return res.status(400).json({ error: 'No OTP sent for this phone' });
  if (Date.now() > entry.expiresAt) {
    otps.delete(phone);
    return res.status(400).json({ error: 'OTP expired' });
  }
  if (entry.otp !== otp) return res.status(400).json({ error: 'Invalid OTP' });

  // OTP is valid — create (or reuse) a Firebase custom token
  try {
    // Use phone as uid. In production, map to your internal users.
    const uid = `wa:${phone}`;
    const additionalClaims = { provider: 'whatsapp' };

    // Create custom token
    const customToken = await admin.auth().createCustomToken(uid, additionalClaims);

    // Optionally: create user record if not exists
    try {
      await admin.auth().getUser(uid);
    } catch (e) {
      try {
        await admin.auth().createUser({ uid, phoneNumber: phone });
        console.log(`Firebase user created: ${uid} (${phone})`);
      } catch (createErr) {
        console.error('Failed to create Firebase user:', createErr);
      }
    }

    // remove used otp
    otps.delete(phone);

    return res.json({ success: true, token: customToken });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Failed to create custom token' });
  }
});

app.listen(PORT, () => console.log(`Server listening on ${PORT}`));
