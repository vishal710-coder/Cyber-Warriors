// server.js
// Breach-report demo: uses HaveIBeenPwned if HIBP_API_KEY provided, otherwise uses built-in demo data.
// Run: HIBP_API_KEY=yourkey SMTP_URL=... node server.js
const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const validator = require('validator');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));

const HIBP_API_KEY = process.env.HIBP_API_KEY || '';
const PORT = process.env.PORT || 3000;

// --- Demo dataset (so the app works without external API key) ---
const DEMO_BREACHES = {
  "pemiblanc": {
    name: "Pemiblanc",
    domain: "pemiblanc.com",
    date: "2018-01-01",
    breachDate: "2018-01-01",
    addedDate: "2018-01-15",
    modifiedDate: "2018-02-01",
    description: "A credential stuffing list known as \"Pemiblanc\" containing 111 million email addresses discovered in 2018. Included email:password pairs.",
    dataClasses: ["Email addresses","Passwords"],
    pwnCount: 114015423,
    passwordStatus: "plaintext",
    verified: false,
    sensitive: true,
    industry: "Miscellaneous"
  },
  "500px": {
    name: "500px",
    domain: "500px.com",
    date: "2018-02-13",
    description: "500px suffered a data breach in 2018 exposing users' names, emails, locations and hashed passwords.",
    dataClasses: ["Usernames","Email addresses","Passwords","Names","Dates of birth","Genders","Geographic locations"],
    pwnCount: 14875273,
    passwordStatus: "hardtocrack",
    verified: true,
    sensitive: false,
    industry: "Entertainment"
  },
  "myfitnesspal": {
    name: "MyFitnessPal",
    domain: "myfitnesspal.com",
    date: "2018-03-01",
    description: "MyFitnessPal breach exposed usernames, passwords, and email addresses. Old passwords later appeared on the dark web.",
    dataClasses: ["Email addresses","Usernames","Passwords","IP addresses"],
    pwnCount: 143570814,
    passwordStatus: "easytocrack",
    verified: true,
    sensitive: false,
    industry: "Health Care"
  }
};

// --- Simple in-memory verification tokens (demo only) ---
const emailVerifyTokens = new Map(); // email -> { token, expires }

// --- Helper: query HIBP account endpoint ---
async function queryHIBP(email) {
  if (!HIBP_API_KEY) return null;
  const url = `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`;
  const resp = await fetch(url, {
    headers: {
      'hibp-api-key': HIBP_API_KEY,
      'user-agent': 'breach-report-demo'
    }
  });
  if (resp.status === 404) return []; // no breach found
  if (!resp.ok) {
    const txt = await resp.text();
    throw new Error(`HIBP error ${resp.status}: ${txt}`);
  }
  const data = await resp.json();
  return data;
}

// --- Risk scoring algorithm (simple, explainable) ---
function computeRiskScore(breaches) {
  // Score 0..100
  // weight by pwnCount and severity (plaintext passwords high weight, verified lowers uncertainty)
  let score = 0;
  for (const b of breaches) {
    const pwn = b.pwnCount || 0;
    // base weight from size (log scale)
    const sizeWeight = Math.min(20, Math.log10(Math.max(1, pwn)) * 2.5); // 0..~20
    // password severity
    let passWeight = 0;
    const pw = (b.passwordStatus || '').toLowerCase();
    if (pw.includes('plain') || pw.includes('plaintext')) passWeight = 25;
    else if (pw.includes('easy')) passWeight = 18;
    else if (pw.includes('hard')) passWeight = 8;
    // sensitive data classes add weight
    const sensitiveClasses = ['Passwords','IP addresses','Dates of birth','Names'];
    const sensCount = (b.dataClasses || []).filter(c => sensitiveClasses.includes(c)).length;
    const sensWeight = Math.min(20, sensCount * 6);

    // smaller penalty/bonus for verified vs unverified
    const verifiedBonus = b.verified ? -4 : 0;

    const breachScore = sizeWeight + passWeight + sensWeight + verifiedBonus;
    score += breachScore;
  }
  score = Math.round(Math.min(100, score));
  return score;
}

// --- Utility: map/normalize HIBP breach to our shape ---
function normalizeBreach(b) {
  return {
    name: b.Name || b.name,
    domain: b.Domain || b.domain,
    description: b.Description || b.description,
    dataClasses: b.DataClasses || b.dataClasses || [],
    pwnCount: b.PwnCount || b.pwnCount || 0,
    passwordStatus: (b.passwordStatus) || (b.password && b.password.toLowerCase && b.password.toLowerCase()) || 'unknown',
    verified: !!(b.IsVerified || b.verified),
    sensitive: !!(b.IsSensitive || b.sensitive),
    addedDate: b.AddedDate || b.addedDate || null,
    breachDate: b.BreachDate || b.breachDate || null,
    industry: b.industry || 'Miscellaneous'
  };
}

// --- API: check email and produce report ---
app.post('/api/report', async (req, res) => {
  try {
    const { email, includeSensitive } = req.body || {};
    if (!email || !validator.isEmail(email)) {
      return res.status(400).json({ error: 'Invalid email' });
    }
    const normalizedEmail = email.toLowerCase().trim();

    // 1) Try HIBP if key present
    let rawBreaches = null;
    let usedHIBP = false;
    if (HIBP_API_KEY) {
      try {
        const hibpResult = await queryHIBP(normalizedEmail);
        rawBreaches = hibpResult;
        usedHIBP = true;
      } catch (err) {
        console.error('HIBP error:', err.message);
        // fall through to demo data
      }
    }

    // 2) If no HIBP or HIBP returned nothing, use demo discovery
    let breaches = [];
    if (Array.isArray(rawBreaches) && rawBreaches.length) {
      breaches = rawBreaches.map(normalizeBreach);
    } else {
      // demo logic: map demo breaches where email domain or local part appears (very simple)
      const localPart = normalizedEmail.split('@')[0];
      const domain = normalizedEmail.split('@')[1] || '';
      // for demo, include all demo breaches if domain includes the provider name OR local part equals 'test' etc.
      const picks = [];
      if (domain.includes('pemiblanc') || localPart === 'test' || domain.endsWith('co')) picks.push(DEMO_BREACHES.pemiblanc);
      if (domain.includes('500px') || localPart === 'test' || domain.endsWith('co')) picks.push(DEMO_BREACHES["500px"]);
      if (domain.includes('myfitnesspal') || localPart === 'test' || domain.endsWith('co')) picks.push(DEMO_BREACHES["myfitnesspal"]);
      // remove duplicates
      const unique = Array.from(new Set(picks.map(p=>p.name))).map(name => Object.values(DEMO_BREACHES).find(d=>d.name===name));
      breaches = unique.map(normalizeBreach);
    }

    // filter sensitive breaches unless includeSensitive true (we'll require verification)
    let sensitiveBreaches = breaches.filter(b => b.sensitive);
    let visibleBreaches = breaches.filter(b => !b.sensitive || includeSensitive);

    // compute counts and categories
    const totalExposed = breaches.length;
    const categories = {};
    for (const b of breaches) {
      for (const c of b.dataClasses || []) {
        categories[c] = (categories[c] || 0) + 1;
      }
    }
    // risk score
    const riskScore = computeRiskScore(breaches);

    // assemble summary & recommendations (simple heuristics)
    const compromisedPasswords = breaches.filter(b => (b.passwordStatus || '').toLowerCase().includes('plain') || (b.dataClasses||[]).includes('Passwords'));
    const recommendations = [];
    if (compromisedPasswords.length) {
      recommendations.push({
        title: 'Compromised Passwords',
        desc: `Breaches with passwords found: ${compromisedPasswords.map(b => b.name).join(', ')}. Recommended: change passwords immediately and use unique passwords.`
      });
    }
    if (riskScore >= 70) {
      recommendations.push({ title: 'High risk', desc: 'Immediate action recommended: password changes, enable 2FA, check financial statements.' });
    } else if (riskScore >= 40) {
      recommendations.push({ title: 'Medium risk', desc: 'Enhance security measures (strong passwords, 2FA) and monitor activity.' });
    } else {
      recommendations.push({ title: 'Low risk', desc: 'Maintain good security hygiene and regular password changes.' });
    }

    // build detailed table entries
    const detailed = visibleBreaches.map(b => ({
      name: b.name,
      domain: b.domain,
      description: b.description,
      pwnCount: b.pwnCount,
      dataClasses: b.dataClasses,
      passwordStatus: b.passwordStatus,
      industry: b.industry
    }));

    // response
    res.json({
      email: normalizedEmail,
      usedHIBP,
      totalExposed,
      breachNames: breaches.map(b=>b.name),
      visibleCount: visibleBreaches.length,
      sensitiveCount: sensitiveBreaches.length,
      breaches: detailed,
      categories,
      riskScore,
      recommendations,
      raw: breaches // raw data (for debugging)
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- Simple email verification token: create token and (optional) send email ---
// NOTE: For demo, nodemailer send is disabled unless SMTP_URL provided.
app.post('/api/request-verify', async (req, res) => {
  const { email } = req.body || {};
  if (!email || !validator.isEmail(email)) return res.status(400).json({ error: 'Invalid email' });
  const token = crypto.randomBytes(3).toString('hex'); // small token for demo
  const expires = Date.now() + 1000 * 60 * 15; // 15 minutes
  emailVerifyTokens.set(email, { token, expires });

  // Optionally send via SMTP if SMTP_URL provided
  const SMTP_URL = process.env.SMTP_URL || '';
  if (SMTP_URL) {
    try {
      const transporter = nodemailer.createTransport(SMTP_URL);
      await transporter.sendMail({
        from: 'no-reply@example.com',
        to: email,
        subject: 'Your verification token',
        text: `Your verification token: ${token}`
      });
      return res.json({ ok: true, sent: true });
    } catch (err) {
      console.error('SMTP send failed:', err.message);
      // fallback to returning token in response (only for demo, NOT production)
      return res.json({ ok: true, sent: false, token });
    }
  }

  // demo: return token in response (so you can test verify flow without email)
  return res.json({ ok: true, token });
});

app.post('/api/verify-token', (req, res) => {
  const { email, token } = req.body || {};
  if (!email || !token) return res.status(400).json({ error: 'Missing' });
  const record = emailVerifyTokens.get(email);
  if (!record || record.expires < Date.now()) return res.status(400).json({ error: 'No token or expired' });
  if (record.token !== token) return res.status(400).json({ error: 'Invalid token' });
  // success: mark verified and remove token
  emailVerifyTokens.delete(email);
  return res.json({ ok: true, verified: true });
});

app.listen(PORT, () => console.log(`Breach-report demo running on http://localhost:${PORT}`));

