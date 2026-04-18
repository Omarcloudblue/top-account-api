require('dotenv').config();
const express = require('express');
const mssql   = require('mssql');
const crypto  = require('crypto');
const path    = require('path');

const app = express();

// ── CORS ──────────────────────────────────────────────────────────────────────
app.use((req, res, next) => {
  const allowed = [
    'http://localhost:3000',
    'http://127.0.0.1:3000',
    'http://localhost:5500',
    'http://127.0.0.1:5500',
    process.env.SITE_ORIGIN,
  ].filter(Boolean);
  const origin = req.headers.origin;
  if (!origin || allowed.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin || '*');
  }
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-api-key');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── Configuración SQL Server (TCP) ────────────────────────────────────────────
const dbConfig = {
  user:     process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  server:   process.env.DB_SERVER,
  database: process.env.DB_NAME,
  options: {
    trustServerCertificate: true,
    enableArithAbort: true,
  },
  port: 1433,
};

// Pool de conexiones (se reutiliza entre requests)
let pool;
async function getPool() {
  if (!pool) pool = await mssql.connect(dbConfig);
  return pool;
}

// ── OTP store en memoria ──────────────────────────────────────────────────────
const otpStore  = new Map();
const OTP_TTL   = 5 * 60 * 1000;

// ── Helpers ───────────────────────────────────────────────────────────────────
function requireApiKey(req, res, next) {
  if (req.headers['x-api-key'] !== process.env.API_KEY)
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  next();
}

function md5Upper(text) {
  return crypto.createHash('md5').update(text).digest('hex').toUpperCase();
}

function generateOtp() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function maskEmail(email) {
  const [user, domain] = email.split('@');
  return `${user.slice(0, 2)}${'*'.repeat(Math.max(1, user.length - 2))}@${domain}`;
}

// ── POST /create-account ──────────────────────────────────────────────────────
app.post('/create-account', requireApiKey, async (req, res) => {
  const { username, password, email } = req.body;

  if (!username || !password || !email)
    return res.status(400).json({ success: false, message: 'username, password y email son requeridos' });
  if (username.length > 50 || password.length > 50 || email.length > 50)
    return res.status(400).json({ success: false, message: 'Los campos no pueden superar 50 caracteres' });
  if (!/^[a-zA-Z0-9_]+$/.test(username))
    return res.status(400).json({ success: false, message: 'El username solo puede contener letras, numeros y guion bajo' });

  try {
    const db = await getPool();

    const check = await db.request()
      .input('name', mssql.VarChar, username)
      .query('SELECT id FROM dbo.account_login WHERE name = @name');

    if (check.recordset.length > 0)
      return res.status(409).json({ success: false, message: 'El nombre de usuario ya existe' });

    await db.request()
      .input('name',             mssql.VarChar, username)
      .input('password',         mssql.VarChar, md5Upper(password))
      .input('originalPassword', mssql.VarChar, password)
      .input('email',            mssql.VarChar, email)
      .query(`INSERT INTO dbo.account_login WITH (HOLDLOCK)
               (name, password, originalPassword, sid, login_status, enable_login_tick, ban, email, total_live_time)
              VALUES (@name, @password, @originalPassword, 0, 0, 0, 0, @email, 0)`);

    console.log(`[${new Date().toISOString()}] Cuenta creada: ${username} (${email})`);
    return res.status(201).json({ success: true, message: `Cuenta '${username}' creada exitosamente` });

  } catch (err) {
    console.error(`[${new Date().toISOString()}] Error /create-account:`, err.message);
    return res.status(500).json({ success: false, message: 'Error interno del servidor' });
  }
});

// ── POST /request-otp ─────────────────────────────────────────────────────────
app.post('/request-otp', requireApiKey, async (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ success: false, message: 'username es requerido' });

  try {
    const db   = await getPool();
    const rows = await db.request()
      .input('name', mssql.VarChar, username)
      .query('SELECT email FROM dbo.account_login WHERE name = @name');

    if (rows.recordset.length === 0)
      return res.status(404).json({ success: false, message: 'No existe una cuenta con ese nombre de usuario' });

    const email = rows.recordset[0].email;
    if (!email?.trim())
      return res.status(400).json({ success: false, message: 'Esta cuenta no tiene un correo registrado' });

    const otp = generateOtp();
    otpStore.set(username.toLowerCase(), { otp, email, expiresAt: Date.now() + OTP_TTL });

    console.log(`[${new Date().toISOString()}] OTP generado para: ${username}`);
    return res.json({ success: true, email: maskEmail(email), otp, fullEmail: email });

  } catch (err) {
    console.error(`[${new Date().toISOString()}] Error /request-otp:`, err.message);
    return res.status(500).json({ success: false, message: 'Error interno del servidor' });
  }
});

// ── POST /verify-otp ──────────────────────────────────────────────────────────
app.post('/verify-otp', requireApiKey, (req, res) => {
  const { username, otp } = req.body;
  if (!username || !otp) return res.status(400).json({ success: false, message: 'username y otp son requeridos' });

  const entry = otpStore.get(username.toLowerCase());
  if (!entry)                    return res.status(400).json({ success: false, message: 'No hay un OTP activo para este usuario. Solicita uno nuevo.' });
  if (Date.now() > entry.expiresAt) { otpStore.delete(username.toLowerCase()); return res.status(400).json({ success: false, message: 'El código ha expirado. Solicita uno nuevo.' }); }
  if (entry.otp !== otp.trim())  return res.status(400).json({ success: false, message: 'Código incorrecto. Verifica tu correo e intenta de nuevo.' });

  return res.json({ success: true, message: 'Código verificado correctamente' });
});

// ── POST /reset-password ──────────────────────────────────────────────────────
app.post('/reset-password', requireApiKey, async (req, res) => {
  const { username, otp, newPassword } = req.body;
  if (!username || !otp || !newPassword) return res.status(400).json({ success: false, message: 'username, otp y newPassword son requeridos' });
  if (newPassword.length < 4 || newPassword.length > 50) return res.status(400).json({ success: false, message: 'La contraseña debe tener entre 4 y 50 caracteres' });

  const entry = otpStore.get(username.toLowerCase());
  if (!entry)                    return res.status(400).json({ success: false, message: 'Sesión expirada. Solicita un nuevo código.' });
  if (Date.now() > entry.expiresAt) { otpStore.delete(username.toLowerCase()); return res.status(400).json({ success: false, message: 'El código ha expirado.' }); }
  if (entry.otp !== otp.trim())  return res.status(400).json({ success: false, message: 'Código inválido.' });

  try {
    const db = await getPool();
    await db.request()
      .input('password',         mssql.VarChar, md5Upper(newPassword))
      .input('originalPassword', mssql.VarChar, newPassword)
      .input('name',             mssql.VarChar, username)
      .query('UPDATE dbo.account_login SET password = @password, originalPassword = @originalPassword WHERE name = @name');

    otpStore.delete(username.toLowerCase());
    console.log(`[${new Date().toISOString()}] Contraseña actualizada: ${username}`);
    return res.json({ success: true, message: `Contraseña de '${username}' actualizada exitosamente` });

  } catch (err) {
    console.error(`[${new Date().toISOString()}] Error /reset-password:`, err.message);
    return res.status(500).json({ success: false, message: 'Error interno del servidor' });
  }
});

// ── GET /health ───────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ── Arrancar servidor ─────────────────────────────────────────────────────────
const PORT = process.env.API_PORT || 3000;
app.listen(PORT, () => {
  console.log(`ToP Account API corriendo en puerto ${PORT}`);
  console.log(`DB: ${process.env.DB_SERVER} / ${process.env.DB_NAME}`);
});
