/* ── Configuración ── */
// En local apunta al mismo server (puerto 3000)
// En producción (Netlify) apunta al tunnel público de la API
const API = (location.hostname === 'localhost' || location.hostname === '127.0.0.1')
  ? ''
  : 'https://squatter-saved-broiler.ngrok-free.dev';
const API_KEY = 'top-sf-secret-key-2024';

/* ── Estado ── */
let forgotUsername = '';
let forgotOtp      = '';

/* ── Helpers de UI ── */
function show(id)  { document.querySelectorAll('.view').forEach(v => v.classList.remove('active')); document.getElementById(id)?.classList.add('active'); }
function err(id, msg) { const el = document.getElementById(id); if (el) { el.textContent = '⚠ ' + msg; el.style.display = 'block'; } }
function clearErr(id)  { const el = document.getElementById(id); if (el) el.style.display = 'none'; }

function showTab(tab) {
  document.getElementById('tabReg').classList.toggle('active', tab === 'register');
  document.getElementById('tabForgot').classList.toggle('active', tab !== 'register');
  clearErr('regError'); clearErr('f1Error'); clearErr('f2Error'); clearErr('f3Error');
  if (tab === 'register') show('vRegister');
  if (tab === 'forgot1')  show('vForgot1');
}

async function apiPost(path, body) {
  const res = await fetch(API + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': API_KEY },
    body: JSON.stringify(body)
  });
  return res.json();
}

/* ── Registro ── */
async function doRegister() {
  const username = document.getElementById('regUser').value.trim();
  const password = document.getElementById('regPass').value;
  const email    = document.getElementById('regEmail').value.trim();

  clearErr('regError');
  if (!/^[a-zA-Z0-9_]+$/.test(username)) return err('regError', 'El usuario solo puede contener letras, números y guion bajo.');
  if (password.length < 4)               return err('regError', 'La contraseña debe tener al menos 4 caracteres.');
  if (!email.includes('@'))              return err('regError', 'Ingresa un email válido.');

  show('vLoading');
  try {
    const data = await apiPost('/create-account', { username, password, email });
    if (data.success) {
      document.getElementById('createdUser').textContent = username;
      show('vSuccess');
    } else {
      show('vRegister');
      err('regError', data.message);
    }
  } catch {
    show('vRegister');
    err('regError', 'No se pudo conectar con el servidor. Verifica que la API esté activa.');
  }
}

function resetForm() {
  document.getElementById('regUser').value = '';
  document.getElementById('regPass').value = '';
  document.getElementById('regEmail').value = '';
  show('vRegister');
}

/* ── Forgot — paso 1: pedir OTP ── */
async function doRequestOtp() {
  const username = document.getElementById('fUser').value.trim();
  clearErr('f1Error');
  if (!username) return err('f1Error', 'Ingresa tu nombre de usuario.');

  forgotUsername = username;
  show('vLoading');
  try {
    const data = await apiPost('/request-otp', { username });
    if (data.success) {
      document.getElementById('maskedEmail').textContent = data.email;
      document.getElementById('fOtp').value = '';
      show('vForgot2');
    } else {
      show('vForgot1');
      err('f1Error', data.message);
    }
  } catch {
    show('vForgot1');
    err('f1Error', 'No se pudo conectar con el servidor.');
  }
}

/* ── Forgot — paso 2: verificar OTP ── */
async function doVerifyOtp() {
  const otp = document.getElementById('fOtp').value.trim();
  clearErr('f2Error');
  if (otp.length !== 6) return err('f2Error', 'El código debe tener 6 dígitos.');

  forgotOtp = otp;
  show('vLoading');
  try {
    const data = await apiPost('/verify-otp', { username: forgotUsername, otp });
    if (data.success) {
      document.getElementById('fNewPass').value = '';
      document.getElementById('fConfirmPass').value = '';
      show('vForgot3');
    } else {
      show('vForgot2');
      err('f2Error', data.message);
    }
  } catch {
    show('vForgot2');
    err('f2Error', 'No se pudo conectar con el servidor.');
  }
}

/* ── Forgot — paso 3: nueva contraseña ── */
async function doResetPassword() {
  const newPassword     = document.getElementById('fNewPass').value;
  const confirmPassword = document.getElementById('fConfirmPass').value;
  clearErr('f3Error');
  if (newPassword.length < 4)         return err('f3Error', 'La contraseña debe tener al menos 4 caracteres.');
  if (newPassword !== confirmPassword) return err('f3Error', 'Las contraseñas no coinciden.');

  show('vLoading');
  try {
    const data = await apiPost('/reset-password', { username: forgotUsername, otp: forgotOtp, newPassword });
    if (data.success) {
      document.getElementById('updatedUser').textContent = forgotUsername;
      show('vForgotOk');
    } else {
      show('vForgot3');
      err('f3Error', data.message);
    }
  } catch {
    show('vForgot3');
    err('f3Error', 'No se pudo conectar con el servidor.');
  }
}
