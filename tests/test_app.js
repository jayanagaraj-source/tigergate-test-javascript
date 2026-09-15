// Runs with no dependencies installed. Exercises the original fixture plus the negative-control module,
// so a regression that accidentally makes safe.js unsafe (or breaks it) is caught.
import assert from 'node:assert/strict';
import { login } from '../src/app.js';
import { equalSafe, hashPasswordSafe, tokenSafe, sha256, encryptSafe, readUploadSafe } from '../src/safe/safe.js';
import crypto from 'node:crypto';

assert.equal(login('admin', 'password123'), true, 'fixture login should accept the fixture password');
assert.equal(login('admin', 'wrong-password'), false, 'fixture login should reject a wrong password');

assert.equal(equalSafe('abc', 'abc'), true);
assert.equal(equalSafe('abc', 'abd'), false);
assert.equal(equalSafe('abc', 'abcd'), false, 'length mismatch must not throw');

assert.notEqual(hashPasswordSafe('pw'), hashPasswordSafe('pw'), 'scrypt output must differ per random salt');
assert.match(tokenSafe(), /^[0-9a-f]{64}$/);
assert.equal(sha256('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');

const key = crypto.randomBytes(32);
const a = encryptSafe('hello', key), b = encryptSafe('hello', key);
assert.notEqual(a.ct.toString('hex'), b.ct.toString('hex'), 'GCM must use a fresh IV per message');

await assert.rejects(readUploadSafe('../../etc/passwd'), 'traversal must be rejected or fail closed');

console.log('ok');
