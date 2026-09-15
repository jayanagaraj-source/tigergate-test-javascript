#!/usr/bin/env node
// Lists every tagged fixture (FIX-<CATEGORY>-<NNN>) in the repo with its location and description.
// Usage: node scripts/list-fixtures.js [--md] [--json]
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

const ROOT = new URL('..', import.meta.url).pathname;
const SKIP = new Set(['node_modules', '.git', 'expected']);
const TAG = /FIX-(SAST|SEC|IAC|SCA)-(\d{3})(?:\.\.(\d{3}))?[:\s]*(.*?)(?=\s*\/?\s*FIX-|$)/g;

function* walk(dir) {
  for (const name of readdirSync(dir)) {
    if (SKIP.has(name) || name === 'package-lock.json' || name.endsWith('.md')) continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) yield* walk(p);
    else yield p;
  }
}

const findings = [];
for (const file of walk(ROOT)) {
  let text;
  try { text = readFileSync(file, 'utf8'); } catch { continue; }
  if (/[\x00-\x08]/.test(text)) continue; // skip binaries
  text.split('\n').forEach((line, i) => {
    for (const m of line.matchAll(TAG)) {
      const [, cat, from, to, desc] = m;
      const id = to ? `FIX-${cat}-${from}..${to}` : `FIX-${cat}-${from}`;
      findings.push({ id, category: cat, file: relative(ROOT, file), line: i + 1, description: desc.replace(/\*\/|-->|\s+$/g, '').trim() });
    }
  });
}
findings.sort((a, b) => a.id.localeCompare(b.id) || a.file.localeCompare(b.file));

const mode = process.argv[2];
if (mode === '--json') {
  console.log(JSON.stringify(findings, null, 2));
} else if (mode === '--md') {
  let cat = '';
  for (const f of findings) {
    if (f.category !== cat) { cat = f.category; console.log(`\n### ${cat}\n\n| ID | Location | Finding |\n|---|---|---|`); }
    console.log(`| ${f.id} | \`${f.file}:${f.line}\` | ${f.description} |`);
  }
} else {
  for (const f of findings) console.log(`${f.id}\t${f.file}:${f.line}\t${f.description}`);
  const byCat = findings.reduce((m, f) => ((m[f.category] = (m[f.category] || 0) + 1), m), {});
  console.error(`\n${findings.length} tagged fixtures: ${Object.entries(byCat).map(([k, v]) => `${k}=${v}`).join(', ')}`);
}
