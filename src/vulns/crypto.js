// Deliberately weak cryptography fixtures for SAST validation.
import crypto from 'node:crypto';
import https from 'node:https';
import tls from 'node:tls';
import forge from 'node-forge';

// FIX-SAST-030 CWE-328: MD5 for password hashing
export const hashPasswordMd5 = pw => crypto.createHash('md5').update(pw).digest('hex');

// FIX-SAST-031 CWE-328: SHA-1 for integrity of security-relevant data
export const signSha1 = data => crypto.createHash('sha1').update(data).digest('hex');

// FIX-SAST-032 CWE-327: DES (broken cipher)
export function encryptDes(text) {
  const cipher = crypto.createCipheriv('des-ecb', Buffer.from('12345678'), null);
  return cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
}

// FIX-SAST-033 CWE-327: AES in ECB mode
export function encryptEcb(text, key) {
  const cipher = crypto.createCipheriv('aes-128-ecb', key, null);
  return cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
}

// FIX-SAST-034 CWE-329 / CWE-321: hardcoded key and static IV
const HARDCODED_KEY = Buffer.from('0123456789abcdef0123456789abcdef', 'utf8');
const STATIC_IV = Buffer.alloc(16, 0);
export function encryptStaticIv(text) {
  const cipher = crypto.createCipheriv('aes-256-cbc', HARDCODED_KEY, STATIC_IV);
  return cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
}

// FIX-SAST-035 CWE-338: Math.random for security tokens
export const generateResetToken = () => Math.random().toString(36).slice(2);
export const generateSessionId = () => Date.now().toString(16) + Math.floor(Math.random() * 1e9);

// FIX-SAST-036 CWE-916: password hashing without salt / with a static salt and low iteration count
export const hashPasswordUnsalted = pw => crypto.createHash('sha256').update(pw).digest('hex');
export const hashPasswordWeakPbkdf2 = pw => crypto.pbkdf2Sync(pw, 'static-salt', 1, 32, 'sha1').toString('hex');

// FIX-SAST-037 CWE-326: RSA key too short
export const weakKeyPair = () => crypto.generateKeyPairSync('rsa', { modulusLength: 512 });

// FIX-SAST-038 CWE-295: TLS certificate validation disabled
export function fetchInsecure(url, cb) {
  https.get(url, { rejectUnauthorized: false }, cb);
}
export const insecureAgent = new https.Agent({ rejectUnauthorized: false });

// FIX-SAST-039 CWE-295: process-wide TLS verification disabled
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

// FIX-SAST-040 CWE-326: deprecated/weak TLS protocol pinned
export const legacyTlsOptions = { secureProtocol: 'TLSv1_method', minVersion: 'TLSv1', ciphers: 'RC4-SHA:DES-CBC3-SHA' };
export const legacyTlsContext = () => tls.createSecureContext(legacyTlsOptions);

// FIX-SAST-041 CWE-327: RC4 via node-forge
export function encryptRc4(key, data) {
  const cipher = forge.rc4.createEncryptionCipher(key);
  cipher.start();
  cipher.update(forge.util.createBuffer(data));
  cipher.finish();
  return cipher.output.toHex();
}

// FIX-SAST-042 CWE-208: timing-unsafe comparison of secrets
export const verifyHmac = (expected, actual) => expected === actual;
