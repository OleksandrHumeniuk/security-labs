const express = require('express');
let _ = null;
try { _ = require('lodash'); } catch (e) {}
const serialize = require('serialize-javascript');
const ejs = require('ejs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const JWT_SECRET = 'hardcoded-secret-key';

const users = [
  { id: 1, username: 'admin', password: 'admin123', role: 'admin' },
  { id: 2, username: 'user', password: 'password', role: 'user' }
];

// VULNERABILITY 1: replaced lodash.merge with safe Object.assign
app.post('/api/config', (req, res) => {
  const defaultConfig = { theme: 'light', language: 'en' };
  const { theme, language } = req.body;
  const merged = Object.assign({}, defaultConfig, { theme, language });
  res.json({ config: merged });
});

// VULNERABILITY 2: Arbitrary Code Execution via serialize-javascript (CVE-2020-7660)
app.get('/api/state', (req, res) => {
  const state = {
    user: req.query.user || 'anonymous',
    timestamp: Date.now(),
    data: req.query.data || null
  };
  const serialized = serialize(state);
  res.send(`<script>window.__STATE__ = ${serialized}</script>`);
});

// VULNERABILITY 3: Server-Side Template Injection via ejs (CVE-2022-29078)
app.get('/api/render', (req, res) => {
  const template = '<h1>Hello, <%= user %></h1>';
  const data = { user: req.query.name || 'World' };
  const options = req.query;
  const html = ejs.render(template, data, options);
  res.send(html);
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username && u.password === password);
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET);
  res.json({ token });
});

app.get('/', (req, res) => {
  res.json({
    message: 'Vulnerable Demo App for Snyk Security Scanning',
    endpoints: [
      'POST /api/config   - Prototype Pollution (lodash)',
      'GET  /api/state     - Code Execution (serialize-javascript)',
      'GET  /api/render    - Template Injection (ejs)',
      'POST /api/login     - JWT Authentication'
    ]
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
