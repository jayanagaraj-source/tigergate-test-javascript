// Deliberately vulnerable web-layer fixtures (XSS, SSRF, redirects, headers, cookies) for SAST validation.
import axios from 'axios';
import fetch from 'node-fetch';
import request from 'request';
import ejs from 'ejs';
import { marked } from 'marked';
import Handlebars from 'handlebars';

// FIX-SAST-050 CWE-79: reflected XSS — unescaped input in HTML response
export function greet(req, res) {
  res.send(`<h1>Hello ${req.query.name}</h1>`);
}

// FIX-SAST-051 CWE-79: XSS via res.write with concatenation
export function search(req, res) {
  res.write('<p>Results for: ' + req.query.q + '</p>');
  res.end();
}

// FIX-SAST-052 CWE-79: XSS through template engine with escaping disabled
export function renderProfile(req, res) {
  const html = ejs.render('<div><%- bio %></div>', { bio: req.body.bio });
  res.send(html);
}

// FIX-SAST-053 CWE-79: Handlebars SafeString bypasses escaping
export function renderComment(req, res) {
  const tpl = Handlebars.compile('<p>{{{comment}}}</p>');
  res.send(tpl({ comment: new Handlebars.SafeString(req.body.comment) }));
}

// FIX-SAST-054 CWE-79: markdown rendered with sanitisation off
export function renderMarkdown(req, res) {
  res.send(marked(req.body.md, { sanitize: false }));
}

// FIX-SAST-055 CWE-1336: server-side template injection — user input becomes the template
export function renderCustom(req, res) {
  res.send(ejs.render(req.body.template, { user: req.user }));
}

// FIX-SAST-056 CWE-601: open redirect
export function redirectBack(req, res) {
  res.redirect(req.query.next);
}

// FIX-SAST-057 CWE-601: open redirect via Location header
export function redirectHeader(req, res) {
  res.setHeader('Location', req.query.url);
  res.status(302).end();
}

// FIX-SAST-058 CWE-918: SSRF — user-controlled URL fetched server-side (axios)
export async function proxy(req, res) {
  const r = await axios.get(req.query.url);
  res.send(r.data);
}

// FIX-SAST-059 CWE-918: SSRF via node-fetch
export async function fetchPreview(req, res) {
  const r = await fetch(`http://${req.body.host}/metadata`);
  res.send(await r.text());
}

// FIX-SAST-060 CWE-918: SSRF via deprecated request lib
export function legacyProxy(req, res) {
  request(req.query.target).pipe(res);
}

// FIX-SAST-061 CWE-942: permissive CORS — wildcard origin with credentials
export function corsMiddleware(req, res, next) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  next();
}

// FIX-SAST-062 CWE-942: CORS reflects the request Origin unconditionally
export function reflectOrigin(req, res, next) {
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  next();
}

// FIX-SAST-063 CWE-614 / CWE-1004: cookie without Secure, HttpOnly, SameSite
export function setSessionCookie(req, res) {
  res.cookie('session', req.session.id, { httpOnly: false, secure: false, sameSite: 'none' });
  res.cookie('remember', 'true');
  res.end();
}

// FIX-SAST-064 CWE-113: HTTP response splitting / header injection
export function setLangHeader(req, res) {
  res.setHeader('Content-Language', req.query.lang);
  res.end();
}

// FIX-SAST-065 CWE-915: mass assignment — request body spread straight into a model update
export async function updateProfile(User, req, res) {
  await User.updateOne({ _id: req.user.id }, { $set: { ...req.body } });
  res.sendStatus(204);
}

// FIX-SAST-066 CWE-209: stack trace returned to the client
export function errorHandler(err, req, res, next) {
  res.status(500).json({ message: err.message, stack: err.stack });
}

// FIX-SAST-067 CWE-200: environment / config leak endpoint
export function debugEnv(req, res) {
  res.json(process.env);
}

// FIX-SAST-068 CWE-352: CSRF protection explicitly disabled
export const csrfOptions = { csrf: false };
export function disableCsrf(csurf) {
  return csurf({ ignoreMethods: ['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'DELETE'] });
}

// FIX-SAST-069 CWE-400: unbounded request body / no rate limit
export const bodyLimits = { limit: '1gb', parameterLimit: 1000000 };
