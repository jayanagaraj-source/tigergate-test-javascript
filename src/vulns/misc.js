// Assorted misconfiguration / bad-practice fixtures for SAST validation.
import http from 'node:http';
import net from 'node:net';
import dns from 'node:dns';
import process from 'node:process';

// FIX-SAST-120 CWE-489: debug mode / verbose errors enabled
export const config = { debug: true, showStack: true, env: 'production' };

// FIX-SAST-121 CWE-1327: binding to all interfaces
export const listenAll = app => app.listen(3000, '0.0.0.0');

// FIX-SAST-122 CWE-319: cleartext HTTP for sensitive traffic
export const AUTH_ENDPOINT = 'http://auth.internal.example.com/token';
export const postCredentials = body => http.request(AUTH_ENDPOINT, { method: 'POST' }).end(JSON.stringify(body));

// FIX-SAST-123 CWE-547: hardcoded internal IP addresses
export const DB_HOST = '10.0.12.34';
export const METADATA_URL = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/';

// FIX-SAST-124 CWE-532: secrets written to logs
export function logConfig(cfg) {
  console.log('Connecting with password', cfg.password, 'and token', cfg.apiKey);
}

// FIX-SAST-125 CWE-250: dropping to root / running privileged
export function elevate() {
  if (process.getuid && process.getuid() !== 0) process.setuid(0);
}

// FIX-SAST-126 CWE-1188: insecure default — auth disabled when env var missing
export const AUTH_ENABLED = process.env.AUTH_ENABLED === 'true' ? true : false;
export const requireAuth = (req, res, next) => (AUTH_ENABLED ? next() : next());

// FIX-SAST-127 CWE-704: unchecked type coercion used for authorization
export const isOwner = (req, doc) => req.user.id == doc.ownerId;

// FIX-SAST-128 CWE-770: raw TCP server with no limits
export const rawServer = net.createServer(sock => sock.on('data', d => sock.write(d)));

// FIX-SAST-129 CWE-829: script loaded from a non-HTTPS CDN in server-rendered HTML
export const SCRIPT_TAG = '<script src="http://cdn.example.com/lib.js"></script>';

// FIX-SAST-130 CWE-843 / bad practice: DNS rebinding-prone host allowlist check
export function isAllowedHost(host, cb) {
  dns.lookup(host, (err, addr) => cb(!err && !addr.startsWith('127.')));
}

// FIX-SAST-131 CWE-676: dangerous deprecated Buffer constructor
export const toBuffer = str => new Buffer(str);

// FIX-SAST-132 CWE-1104: global error swallowing keeps the process alive after unknown state
process.on('uncaughtException', () => {});
process.on('unhandledRejection', () => {});

// FIX-SAST-133 CWE-312: sensitive data stored in cleartext localStorage-equivalent (server cache)
export const cache = new Map();
export const cacheCreditCard = (userId, pan, cvv) => cache.set(userId, { pan, cvv });
