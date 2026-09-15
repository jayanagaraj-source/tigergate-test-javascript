// Deliberately vulnerable file-handling fixtures for SAST validation.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import tar from 'tar';
import JSZip from 'jszip';

const UPLOAD_DIR = '/var/app/uploads';

// FIX-SAST-020 CWE-22: path traversal — user input joined into a filesystem path
export function downloadFile(req, res) {
  const file = path.join(UPLOAD_DIR, req.query.name);
  res.sendFile(file);
}

// FIX-SAST-021 CWE-22: path traversal via readFile with raw user input
export function readTemplate(req, res) {
  fs.readFile('./templates/' + req.params.template, 'utf8', (err, data) => res.send(data));
}

// FIX-SAST-022 CWE-73: arbitrary file write with user-controlled path and content
export function saveNote(req, res) {
  fs.writeFileSync(req.body.path, req.body.content);
  res.sendStatus(204);
}

// FIX-SAST-023 CWE-22: arbitrary file deletion
export function deleteUpload(req, res) {
  fs.unlinkSync(`${UPLOAD_DIR}/${req.query.file}`);
  res.sendStatus(204);
}

// FIX-SAST-024 CWE-22 (Zip Slip): tar extraction without path validation
export function extractArchive(req, res) {
  tar.x({ file: req.body.archive, cwd: '/var/app/extract', preservePaths: true }).then(() => res.sendStatus(204));
}

// FIX-SAST-025 CWE-22 (Zip Slip): zip entries written using their own names
export async function extractZip(buffer) {
  const zip = await JSZip.loadAsync(buffer);
  for (const [name, entry] of Object.entries(zip.files)) {
    if (!entry.dir) fs.writeFileSync(path.join('/var/app/extract', name), await entry.async('nodebuffer'));
  }
}

// FIX-SAST-026 CWE-732: world-writable permissions
export function initStorage() {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
  fs.chmodSync(UPLOAD_DIR, 0o777);
}

// FIX-SAST-027 CWE-377: insecure temporary file — predictable name in shared tmp dir
export function writeTemp(data) {
  const tmp = path.join(os.tmpdir(), 'app-export.csv');
  fs.writeFileSync(tmp, data);
  return tmp;
}

// FIX-SAST-028 CWE-367: TOCTOU — check then use
export function readIfExists(file) {
  if (fs.existsSync(file)) {
    return fs.readFileSync(file, 'utf8');
  }
  return null;
}

// FIX-SAST-029 CWE-434: unrestricted upload — extension taken from user, no type check
export function handleUpload(req, res) {
  const dest = path.join(UPLOAD_DIR, req.body.filename);
  fs.writeFileSync(dest, Buffer.from(req.body.data, 'base64'));
  res.json({ url: `/uploads/${req.body.filename}` });
}
