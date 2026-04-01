require('dotenv').config();

const express = require('express');
const bcrypt = require('bcrypt');
const { authenticator } = require('otplib');
const QRCode = require('qrcode');
const { v4: uuidv4 } = require('uuid');
const TelegramBot = require('node-telegram-bot-api');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const DATA_DIR = path.join(__dirname, 'data');
const ACCOUNTS_FILE = path.join(DATA_DIR, 'accounts.json');
const PIN_REENTRY_MS = 60 * 1000;

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}
if (!fs.existsSync(ACCOUNTS_FILE)) {
  fs.writeFileSync(ACCOUNTS_FILE, '[]', 'utf-8');
}

const bot = new TelegramBot(process.env.TELEGRAM_BOT_TOKEN);

// In-memory stores
const pendingRegCodes = new Map();   // phone -> { code, telegramChatId, expiresAt }
const verifiedPhones = new Set();
const pendingAccounts = new Map();   // phone -> { passwordHash, totpSecret }
const sessions = new Map();          // sessionId -> { phone, pinVerifiedAt }
const pendingLogins = new Map();     // tempToken -> { phone, step }
const recoveryCodes = new Map();     // phone -> { code, telegramChatId, expiresAt }
const recoveryVerified = new Set();

// --- Helpers ---

function loadAccounts() {
  const raw = fs.readFileSync(ACCOUNTS_FILE, 'utf-8');
  return JSON.parse(raw);
}

function saveAccounts(accounts) {
  fs.writeFileSync(ACCOUNTS_FILE, JSON.stringify(accounts, null, 2), 'utf-8');
}

function findAccount(phone) {
  return loadAccounts().find(a => a.phone === phone);
}

function updateAccount(phone, updates) {
  const accounts = loadAccounts();
  const idx = accounts.findIndex(a => a.phone === phone);
  if (idx === -1) return null;
  Object.assign(accounts[idx], updates);
  saveAccounts(accounts);
  return accounts[idx];
}

function getSessionFromReq(req) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) return null;
  return sessions.get(header.slice(7)) || null;
}

setInterval(() => {
  const now = Date.now();
  for (const [phone, entry] of pendingRegCodes) {
    if (entry.expiresAt < now) pendingRegCodes.delete(phone);
  }
  for (const [phone, entry] of recoveryCodes) {
    if (entry.expiresAt < now) recoveryCodes.delete(phone);
  }
}, 60_000);

app.post('/api/register/send-code', async (req, res) => {
  try {
    const { phone, telegramChatId } = req.body;
    if (!phone || !telegramChatId) {
      return res.status(400).json({ error: 'Phone and Telegram Chat ID are required' });
    }

    const accounts = loadAccounts();
    if (accounts.find(a => a.phone === phone)) {
      return res.status(409).json({ error: 'An account with this phone already exists' });
    }

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    pendingRegCodes.set(phone, { code, telegramChatId, expiresAt: Date.now() + 5 * 60 * 1000 });

    await bot.sendMessage(telegramChatId, `Your messenger verification code: ${code}\n\nThis code expires in 5 minutes.`);

    res.json({ success: true, message: 'Verification code sent to Telegram' });
  } catch (err) {
    console.error('register/send-code error:', err.message);
    res.status(500).json({ error: 'Failed to send verification code. Check your Bot Token and Chat ID.' });
  }
});

app.post('/api/register/verify-code', (req, res) => {
  const { phone, code } = req.body;
  if (!phone || !code) {
    return res.status(400).json({ error: 'Phone and code are required' });
  }

  const entry = pendingRegCodes.get(phone);
  if (!entry) {
    return res.status(400).json({ error: 'No pending code for this phone. Request a new one.' });
  }
  if (Date.now() > entry.expiresAt) {
    pendingRegCodes.delete(phone);
    return res.status(400).json({ error: 'Code expired. Request a new one.' });
  }
  if (entry.code !== code) {
    return res.status(400).json({ error: 'Invalid code' });
  }

  pendingRegCodes.delete(phone);
  verifiedPhones.add(phone);
  res.json({ success: true, message: 'Phone verified successfully' });
});

app.post('/api/register/set-password', async (req, res) => {
  try {
    const { phone, password } = req.body;
    if (!phone || !password) {
      return res.status(400).json({ error: 'Phone and password are required' });
    }
    if (!verifiedPhones.has(phone)) {
      return res.status(403).json({ error: 'Phone not verified. Complete OTP step first.' });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const totpSecret = authenticator.generateSecret();
    pendingAccounts.set(phone, { passwordHash, totpSecret });

    const otpauth = authenticator.keyuri(phone, 'MessengerApp', totpSecret);
    const qrCodeDataUrl = await QRCode.toDataURL(otpauth);

    res.json({
      success: true,
      totpSecret,
      qrCode: qrCodeDataUrl,
      message: 'Scan the QR code with Google Authenticator, then enter the token to complete registration.',
    });
  } catch (err) {
    console.error('register/set-password error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/register/verify-2fa', (req, res) => {
  const { phone, token } = req.body;
  if (!phone || !token) {
    return res.status(400).json({ error: 'Phone and TOTP token are required' });
  }

  const pending = pendingAccounts.get(phone);
  if (!pending) {
    return res.status(400).json({ error: 'No pending account. Complete previous steps first.' });
  }

  const isValid = authenticator.check(token, pending.totpSecret);
  if (!isValid) {
    return res.status(400).json({ error: 'Invalid 2FA token. Try again.' });
  }

  const account = {
    id: uuidv4(),
    phone,
    passwordHash: pending.passwordHash,
    totpSecret: pending.totpSecret,
    createdAt: new Date().toISOString(),
  };

  const accounts = loadAccounts();
  accounts.push(account);
  saveAccounts(accounts);

  pendingAccounts.delete(phone);
  verifiedPhones.delete(phone);

  res.json({
    success: true,
    message: 'Account created successfully!',
    account: { id: account.id, phone: account.phone, createdAt: account.createdAt },
  });
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { phone, password } = req.body;
    if (!phone || !password) {
      return res.status(400).json({ error: 'Phone and password are required' });
    }

    const account = findAccount(phone);
    if (!account) {
      return res.status(401).json({ error: 'Invalid phone or password' });
    }

    const match = await bcrypt.compare(password, account.passwordHash);
    if (!match) {
      return res.status(401).json({ error: 'Invalid phone or password' });
    }

    const tempToken = uuidv4();
    pendingLogins.set(tempToken, { phone, step: 'need2fa' });

    res.json({ success: true, tempToken, message: 'Credentials verified. Enter your 2FA code.' });
  } catch (err) {
    console.error('auth/login error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/verify-2fa', (req, res) => {
  const { tempToken, token } = req.body;
  if (!tempToken || !token) {
    return res.status(400).json({ error: 'Temp token and TOTP code are required' });
  }

  const pending = pendingLogins.get(tempToken);
  if (!pending || pending.step !== 'need2fa') {
    return res.status(400).json({ error: 'Invalid or expired login session' });
  }

  const account = findAccount(pending.phone);
  if (!account) {
    return res.status(400).json({ error: 'Account not found' });
  }

  const isValid = authenticator.check(token, account.totpSecret);
  if (!isValid) {
    return res.status(400).json({ error: 'Invalid 2FA code. Try again.' });
  }

  const hasPin = !!account.pinHash;
  pending.step = 'needPin';

  res.json({
    success: true,
    hasPin,
    message: hasPin
      ? 'Enter your PIN code to complete login.'
      : 'Create a 4-digit PIN code for quick access.',
  });
});

app.post('/api/auth/set-pin', async (req, res) => {
  try {
    const { tempToken, pin } = req.body;
    if (!tempToken || !pin) {
      return res.status(400).json({ error: 'Temp token and PIN are required' });
    }
    if (!/^\d{4}$/.test(pin)) {
      return res.status(400).json({ error: 'PIN must be exactly 4 digits' });
    }

    const pending = pendingLogins.get(tempToken);
    if (!pending || pending.step !== 'needPin') {
      return res.status(400).json({ error: 'Complete previous steps first' });
    }

    const pinHash = await bcrypt.hash(pin, 10);
    updateAccount(pending.phone, { pinHash });

    const sessionId = uuidv4();
    sessions.set(sessionId, { phone: pending.phone, pinVerifiedAt: Date.now() });
    pendingLogins.delete(tempToken);

    res.json({
      success: true,
      sessionId,
      pinReentryMinutes: PIN_REENTRY_MS / 60000,
      message: 'PIN created. You are now logged in!',
    });
  } catch (err) {
    console.error('auth/set-pin error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/verify-pin', async (req, res) => {
  try {
    const { tempToken, pin } = req.body;
    if (!tempToken || !pin) {
      return res.status(400).json({ error: 'Temp token and PIN are required' });
    }

    const pending = pendingLogins.get(tempToken);
    if (!pending || pending.step !== 'needPin') {
      return res.status(400).json({ error: 'Complete previous steps first' });
    }

    const account = findAccount(pending.phone);
    if (!account || !account.pinHash) {
      return res.status(400).json({ error: 'No PIN set for this account' });
    }

    const match = await bcrypt.compare(pin, account.pinHash);
    if (!match) {
      return res.status(400).json({ error: 'Invalid PIN' });
    }

    const sessionId = uuidv4();
    sessions.set(sessionId, { phone: pending.phone, pinVerifiedAt: Date.now() });
    pendingLogins.delete(tempToken);

    res.json({
      success: true,
      sessionId,
      pinReentryMinutes: PIN_REENTRY_MS / 60000,
      message: 'Login successful!',
    });
  } catch (err) {
    console.error('auth/verify-pin error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/auth/session', (req, res) => {
  const session = getSessionFromReq(req);
  if (!session) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  const elapsed = Date.now() - session.pinVerifiedAt;
  const pinExpired = elapsed >= PIN_REENTRY_MS;

  res.json({
    phone: session.phone,
    pinExpired,
    nextPinReentryIn: Math.max(0, PIN_REENTRY_MS - elapsed),
    pinReentryMinutes: PIN_REENTRY_MS / 60000,
  });
});

app.post('/api/auth/reenter-pin', async (req, res) => {
  try {
    const session = getSessionFromReq(req);
    if (!session) {
      return res.status(401).json({ error: 'Not authenticated' });
    }

    const { pin } = req.body;
    if (!pin) {
      return res.status(400).json({ error: 'PIN is required' });
    }

    const account = findAccount(session.phone);
    if (!account || !account.pinHash) {
      return res.status(400).json({ error: 'Account or PIN not found' });
    }

    const match = await bcrypt.compare(pin, account.pinHash);
    if (!match) {
      return res.status(400).json({ error: 'Invalid PIN' });
    }

    session.pinVerifiedAt = Date.now();

    res.json({
      success: true,
      nextPinReentryIn: PIN_REENTRY_MS,
      message: 'PIN confirmed. Session extended.',
    });
  } catch (err) {
    console.error('auth/reenter-pin error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  const header = req.headers.authorization;
  if (header && header.startsWith('Bearer ')) {
    sessions.delete(header.slice(7));
  }
  res.json({ success: true, message: 'Logged out' });
});

app.post('/api/recovery/send-code', async (req, res) => {
  try {
    const { phone, telegramChatId } = req.body;
    if (!phone || !telegramChatId) {
      return res.status(400).json({ error: 'Phone and Telegram Chat ID are required' });
    }

    const account = findAccount(phone);
    if (!account) {
      return res.status(404).json({ error: 'Account not found' });
    }

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    recoveryCodes.set(phone, { code, telegramChatId, expiresAt: Date.now() + 5 * 60 * 1000 });

    await bot.sendMessage(telegramChatId, `Your account recovery code: ${code}\n\nThis code expires in 5 minutes.`);

    res.json({ success: true, message: 'Recovery code sent to Telegram' });
  } catch (err) {
    console.error('recovery/send-code error:', err.message);
    res.status(500).json({ error: 'Failed to send recovery code. Check Bot Token and Chat ID.' });
  }
});

app.post('/api/recovery/verify-code', (req, res) => {
  const { phone, code } = req.body;
  if (!phone || !code) {
    return res.status(400).json({ error: 'Phone and code are required' });
  }

  const entry = recoveryCodes.get(phone);
  if (!entry) {
    return res.status(400).json({ error: 'No pending recovery code. Request a new one.' });
  }
  if (Date.now() > entry.expiresAt) {
    recoveryCodes.delete(phone);
    return res.status(400).json({ error: 'Code expired. Request a new one.' });
  }
  if (entry.code !== code) {
    return res.status(400).json({ error: 'Invalid code' });
  }

  recoveryCodes.delete(phone);
  recoveryVerified.add(phone);

  const account = findAccount(phone);
  const hasPin = !!(account && account.pinHash);

  res.json({ success: true, hasPin, message: 'Code verified.' });
});

app.post('/api/recovery/confirm-pin', async (req, res) => {
  try {
    const { phone, pin } = req.body;
    if (!phone || !pin) {
      return res.status(400).json({ error: 'Phone and PIN are required' });
    }
    if (!recoveryVerified.has(phone)) {
      return res.status(403).json({ error: 'Complete OTP verification first' });
    }

    const account = findAccount(phone);
    if (!account || !account.pinHash) {
      return res.status(400).json({ error: 'No PIN set for this account' });
    }

    const match = await bcrypt.compare(pin, account.pinHash);
    if (!match) {
      return res.status(400).json({ error: 'Invalid PIN' });
    }

    res.json({ success: true, message: 'PIN confirmed. You can now set a new password.' });
  } catch (err) {
    console.error('recovery/confirm-pin error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/recovery/set-password', async (req, res) => {
  try {
    const { phone, password } = req.body;
    if (!phone || !password) {
      return res.status(400).json({ error: 'Phone and new password are required' });
    }
    if (!recoveryVerified.has(phone)) {
      return res.status(403).json({ error: 'Complete recovery verification first' });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    updateAccount(phone, { passwordHash });
    recoveryVerified.delete(phone);

    res.json({ success: true, message: 'Password updated successfully. You can now log in.' });
  } catch (err) {
    console.error('recovery/set-password error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Messenger auth server running on http://localhost:${PORT}`);
  console.log(`Accounts file: ${ACCOUNTS_FILE}`);
  console.log(`PIN re-entry interval: ${PIN_REENTRY_MS / 60000} minute(s)`);
});
