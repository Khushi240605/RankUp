// ============================================
// RankUp — Complete Login Backend (single file)
// Run: node server.js
// ============================================

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const { OAuth2Client } = require('google-auth-library');
require('dotenv').config();

// ── Config ───────────────────────────────────
const PORT          = process.env.PORT            || 5000;
const JWT_SECRET    = process.env.JWT_SECRET      || 'change-this-in-production';
const SALT_ROUNDS   = 12;
const GOOGLE_CLIENT = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// ── Database (PostgreSQL) ────────────────────
const db = new Pool({
  host:     process.env.DB_HOST     || 'localhost',
  port:     process.env.DB_PORT     || 5432,
  database: process.env.DB_NAME     || 'rankup',
  user:     process.env.DB_USER     || 'postgres',
  password: process.env.DB_PASSWORD || 'yourpassword',
});

// ── Create users table if it doesn't exist ───
async function initDB() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS users (
      id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name                VARCHAR(100),
      email               VARCHAR(255) UNIQUE NOT NULL,
      password_hash       VARCHAR(255),
      google_id           VARCHAR(255) UNIQUE,
      role                VARCHAR(20) DEFAULT 'student',
      reset_token         VARCHAR(255),
      reset_token_expires TIMESTAMPTZ,
      created_at          TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_users_email     ON users(email);
    CREATE INDEX IF NOT EXISTS idx_users_google_id ON users(google_id);
  `);
  console.log('✅ Database ready');
}

// ── App setup ────────────────────────────────
const app = express();
app.use(helmet());
app.use(cors({ origin: process.env.CLIENT_URL || 'http://localhost:3000', credentials: true }));
app.use(express.json());

// Brute-force protection on all auth routes
app.use('/api/auth', rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many attempts. Try again in 15 minutes.' },
}));

// ── Helpers ──────────────────────────────────
const makeToken = (user, rememberMe = false) =>
  jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET,
    { expiresIn: rememberMe ? '30d' : '1d' });

const safeUser = ({ password_hash, reset_token, reset_token_expires, ...u }) => u;

// ── Health check ─────────────────────────────
app.get('/health', (_, res) => res.json({ status: 'ok' }));

// ============================================
// POST /api/auth/signup
// Body: { name, email, password }
// ============================================
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!email || !password)      return res.status(400).json({ error: 'Email and password are required.' });
    if (password.length < 8)      return res.status(400).json({ error: 'Password must be at least 8 characters.' });

    const exists = await db.query('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]);
    if (exists.rows.length)       return res.status(409).json({ error: 'An account with this email already exists.' });

    const password_hash = await bcrypt.hash(password, SALT_ROUNDS);
    const { rows } = await db.query(
      'INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING *',
      [name || null, email.toLowerCase(), password_hash]
    );

    res.status(201).json({ token: makeToken(rows[0]), user: safeUser(rows[0]) });
  } catch (err) {
    console.error('Signup error:', err.message);
    res.status(500).json({ error: 'Signup failed. Please try again.' });
  }
});

// ============================================
// POST /api/auth/login
// Body: { email, password, rememberMe }
// ============================================
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password, rememberMe = false } = req.body;

    if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });

    const { rows } = await db.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    const user = rows[0];

    if (!user || !user.password_hash)               return res.status(401).json({ error: 'Invalid email or password.' });
    if (!await bcrypt.compare(password, user.password_hash)) return res.status(401).json({ error: 'Invalid email or password.' });

    res.json({ token: makeToken(user, rememberMe), user: safeUser(user) });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ error: 'Login failed. Please try again.' });
  }
});

// ============================================
// POST /api/auth/google
// Body: { credential }  ← Google ID token from frontend
// ============================================
app.post('/api/auth/google', async (req, res) => {
  try {
    const { credential } = req.body;
    if (!credential) return res.status(400).json({ error: 'Google credential is required.' });

    const ticket  = await GOOGLE_CLIENT.verifyIdToken({ idToken: credential, audience: process.env.GOOGLE_CLIENT_ID });
    const { sub: google_id, email, name } = ticket.getPayload();

    let { rows } = await db.query('SELECT * FROM users WHERE google_id = $1 OR email = $2', [google_id, email]);
    let user = rows[0];

    if (!user) {
      // New user — create account
      ({ rows } = await db.query(
        'INSERT INTO users (name, email, google_id) VALUES ($1, $2, $3) RETURNING *',
        [name, email, google_id]
      ));
      user = rows[0];
    } else if (!user.google_id) {
      // Existing email user — link Google account
      ({ rows } = await db.query(
        'UPDATE users SET google_id = $1 WHERE id = $2 RETURNING *',
        [google_id, user.id]
      ));
      user = rows[0];
    }

    res.json({ token: makeToken(user), user: safeUser(user) });
  } catch (err) {
    console.error('Google auth error:', err.message);
    res.status(401).json({ error: 'Google login failed. Please try again.' });
  }
});

// ============================================
// POST /api/auth/forgot-password
// Body: { email }
// ============================================
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required.' });

    const { rows } = await db.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    const user = rows[0];

    // Always return success (don't reveal if email exists)
    if (!user) return res.json({ message: 'If this email exists, a reset link has been sent.' });

    const resetToken = crypto.randomBytes(32).toString('hex');
    const expires    = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    await db.query(
      'UPDATE users SET reset_token = $1, reset_token_expires = $2 WHERE id = $3',
      [resetToken, expires, user.id]
    );

    // TODO: plug in an email service (e.g. Nodemailer, SendGrid) here
    console.log(`📧 Reset link → http://localhost:3000/reset-password?token=${resetToken}`);

    res.json({ message: 'If this email exists, a reset link has been sent.' });
  } catch (err) {
    console.error('Forgot password error:', err.message);
    res.status(500).json({ error: 'Failed to process request.' });
  }
});

// ============================================
// POST /api/auth/reset-password
// Body: { token, newPassword }
// ============================================
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    if (!token || !newPassword)  return res.status(400).json({ error: 'Token and new password are required.' });
    if (newPassword.length < 8)  return res.status(400).json({ error: 'Password must be at least 8 characters.' });

    const { rows } = await db.query(
      'SELECT * FROM users WHERE reset_token = $1 AND reset_token_expires > NOW()',
      [token]
    );
    if (!rows[0]) return res.status(400).json({ error: 'Reset link is invalid or has expired.' });

    const password_hash = await bcrypt.hash(newPassword, SALT_ROUNDS);
    await db.query(
      'UPDATE users SET password_hash = $1, reset_token = NULL, reset_token_expires = NULL WHERE id = $2',
      [password_hash, rows[0].id]
    );

    res.json({ message: 'Password reset successfully. You can now log in.' });
  } catch (err) {
    console.error('Reset password error:', err.message);
    res.status(500).json({ error: 'Password reset failed.' });
  }
});

// ── Global error handler ─────────────────────
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong.' });
});

// ── Start ─────────────────────────────────────
initDB().then(() => {
  app.listen(PORT, () => console.log(`✅ RankUp running → http://localhost:${PORT}`));
}).catch(err => {
  console.error('❌ Failed to connect to database:', err.message);
  process.exit(1);
});