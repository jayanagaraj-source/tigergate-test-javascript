// Deliberately vulnerable injection fixtures for SAST validation. Never run against real systems.
import { exec, execSync, spawn } from 'node:child_process';
import vm from 'node:vm';
import mysql from 'mysql';
import mongoose from 'mongoose';
import shell from 'shelljs';

const db = mysql.createConnection({ host: 'localhost', user: 'root', password: 'root', database: 'app' });
const User = mongoose.model('User', new mongoose.Schema({ username: String, password: String }));

// FIX-SAST-001 CWE-89: SQL injection via string concatenation
export function findUserByName(req, res) {
  db.query("SELECT * FROM users WHERE name = '" + req.query.name + "'", (err, rows) => res.json(rows));
}

// FIX-SAST-002 CWE-89: SQL injection via template literal
export function findOrder(req, res) {
  const sql = `SELECT * FROM orders WHERE id = ${req.params.id} ORDER BY ${req.query.sort}`;
  db.query(sql, (err, rows) => res.json(rows));
}

// FIX-SAST-003 CWE-943: NoSQL injection — user-controlled object passed straight to the query
export async function loginNoSql(req, res) {
  const user = await User.findOne({ username: req.body.username, password: req.body.password });
  res.json({ ok: !!user });
}

// FIX-SAST-004 CWE-943: NoSQL $where with string interpolation (server-side JS injection)
export async function searchNoSql(req, res) {
  const users = await User.find({ $where: `this.username.startsWith('${req.query.q}')` });
  res.json(users);
}

// FIX-SAST-005 CWE-78: OS command injection via exec with interpolated input
export function pingHost(req, res) {
  exec(`ping -c 1 ${req.query.host}`, (err, stdout) => res.send(stdout));
}

// FIX-SAST-006 CWE-78: command injection via execSync + concatenation
export function gitLog(req, res) {
  const out = execSync('git log --oneline -n 5 -- ' + req.query.path);
  res.send(out.toString());
}

// FIX-SAST-007 CWE-78: spawn with shell: true and user input
export function listDir(req, res) {
  const child = spawn('ls -la ' + req.query.dir, { shell: true });
  child.stdout.pipe(res);
}

// FIX-SAST-008 CWE-78: shelljs.exec with user input
export function diskUsage(req, res) {
  res.send(shell.exec(`du -sh ${req.query.dir}`).stdout);
}

// FIX-SAST-009 CWE-95: eval of user input
export function calculate(req, res) {
  res.json({ result: eval(req.query.expr) });
}

// FIX-SAST-010 CWE-95: new Function with user input
export function runFormula(req, res) {
  const fn = new Function('x', `return ${req.body.formula};`);
  res.json({ result: fn(42) });
}

// FIX-SAST-011 CWE-94: vm.runInNewContext is not a sandbox
export function runScript(req, res) {
  res.json({ result: vm.runInNewContext(req.body.code, { console }) });
}

// FIX-SAST-012 CWE-95: setTimeout with a string argument (implicit eval)
export function scheduleCallback(req) {
  setTimeout(`console.log("${req.query.msg}")`, 100);
}

// FIX-SAST-013 CWE-117: log injection — raw user input written to logs
export function auditLog(req) {
  console.log('User login attempt: ' + req.body.username);
}

// FIX-SAST-014 CWE-90: LDAP injection
export function ldapSearch(client, req, res) {
  const filter = `(&(uid=${req.query.user})(objectClass=person))`;
  client.search('ou=people,dc=example,dc=com', { filter }, (err, r) => res.json(r));
}
