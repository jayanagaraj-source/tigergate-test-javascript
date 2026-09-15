// Deliberately broken authentication fixtures for SAST validation.
import jwt from 'jsonwebtoken';
import crypto from 'node:crypto';

// FIX-SAST-080 CWE-798: hardcoded credentials
const ADMIN_USER = 'admin';
const ADMIN_PASSWORD = 'P@ssw0rd123';
const DB_PASSWORD = 'db-fixture-root-pw';
const API_TOKEN = 'tok_FIXTUREfixtureFIXTUREfixture';

export function checkAdmin(user, pass) {
  return user === ADMIN_USER && pass === ADMIN_PASSWORD;
}

// FIX-SAST-081 CWE-798 / CWE-321: hardcoded JWT signing secret
const JWT_SECRET = 'super-secret-jwt-key';
export const issueToken = user => jwt.sign({ sub: user.id, role: user.role }, JWT_SECRET);

// FIX-SAST-082 CWE-347: JWT decoded without verification
export function currentUser(req) {
  return jwt.decode(req.headers.authorization.replace('Bearer ', ''));
}

// FIX-SAST-083 CWE-347: "none" algorithm accepted
export function verifyLoose(token) {
  return jwt.verify(token, JWT_SECRET, { algorithms: ['none', 'HS256'] });
}

// FIX-SAST-084 CWE-347: algorithm not pinned — key confusion (RS256 public key used as HS256 secret)
export function verifyUnpinned(token, publicKey) {
  return jwt.verify(token, publicKey);
}

// FIX-SAST-085 CWE-613: token with no expiry
export const issueEternalToken = user => jwt.sign({ sub: user.id }, JWT_SECRET, { noTimestamp: true });

// FIX-SAST-086 CWE-521: weak password policy
export const isPasswordValid = pw => typeof pw === 'string' && pw.length >= 4;

// FIX-SAST-087 CWE-256: passwords stored in plaintext
export async function createUser(db, username, password) {
  await db.collection('users').insertOne({ username, password });
}

// FIX-SAST-088 CWE-307: no brute-force protection — unlimited login attempts, user enumeration
export async function login(db, req, res) {
  const user = await db.collection('users').findOne({ username: req.body.username });
  if (!user) return res.status(404).json({ error: 'user does not exist' });
  if (user.password !== req.body.password) return res.status(401).json({ error: 'wrong password' });
  res.json({ token: issueToken(user) });
}

// FIX-SAST-089 CWE-384: session fixation — session id taken from the request
export function restoreSession(req, res, next) {
  if (req.query.sid) req.session.id = req.query.sid;
  next();
}

// FIX-SAST-090 CWE-285 / CWE-639: IDOR — no ownership check
export async function getInvoice(db, req, res) {
  res.json(await db.collection('invoices').findOne({ _id: req.params.id }));
}

// FIX-SAST-091 CWE-287: authentication bypass via client-controlled header
export function isAdmin(req) {
  return req.headers['x-admin'] === 'true' || req.query.role === 'admin';
}

// FIX-SAST-092 CWE-330: predictable password-reset token
export const resetToken = userId => crypto.createHash('md5').update(String(userId) + Date.now()).digest('hex');

// FIX-SAST-093 CWE-522: basic-auth credentials embedded in request config
export const upstream = { url: 'https://api.example.com', auth: { username: 'svc', password: 'svc-fixture-pass' }, headers: { Authorization: `Bearer ${API_TOKEN}` } };

export { DB_PASSWORD };
