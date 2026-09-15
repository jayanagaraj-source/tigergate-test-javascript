// NEGATIVE CONTROLS. Secure implementations of patterns that appear vulnerably in ../vulns.
// A scanner should report nothing in this file; every finding here counts as a false positive.
import { execFile } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

const UPLOAD_DIR = path.resolve('/var/app/uploads');

// Parameterised query — not SQL injection.
export const findUserSafe = (db, name) => db.query('SELECT * FROM users WHERE name = ?', [name]);

// Argument array without a shell — not command injection.
export const pingSafe = (host, cb) => execFile('ping', ['-c', '1', host], cb);

// Traversal-safe path handling.
export async function readUploadSafe(name) {
  const target = path.resolve(UPLOAD_DIR, path.basename(name));
  if (!target.startsWith(UPLOAD_DIR + path.sep)) throw new Error('invalid path');
  return fs.readFile(target);
}

// Strong hashing and CSPRNG.
export const hashPasswordSafe = pw => crypto.scryptSync(pw, crypto.randomBytes(16), 64).toString('hex');
export const tokenSafe = () => crypto.randomBytes(32).toString('hex');
export const sha256 = data => crypto.createHash('sha256').update(data).digest('hex');

// Constant-time comparison.
export function equalSafe(a, b) {
  const ba = Buffer.from(a), bb = Buffer.from(b);
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}

// Authenticated encryption with a fresh IV per message.
export function encryptSafe(plaintext, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return { iv, ct, tag: cipher.getAuthTag() };
}

// Redirect restricted to a relative path allowlist.
export function redirectSafe(res, next) {
  const dest = typeof next === 'string' && /^\/[a-z0-9/_-]*$/i.test(next) ? next : '/';
  res.redirect(dest);
}

// Escaped HTML output.
const escapeHtml = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
export const greetSafe = (res, name) => res.send(`<h1>Hello ${escapeHtml(name)}</h1>`);

// Secrets sourced from the environment, not literals. The variable *name* alone is not a secret.
export const dbPassword = () => process.env.DB_PASSWORD;

// Example/documentation strings that look like secrets but are canonical placeholders.
export const EXAMPLE_KEY_FORMAT = 'AKIA................';
export const DOCS_TOKEN_HINT = 'ghp_<36 characters>';
