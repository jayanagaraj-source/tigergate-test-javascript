// Express app that wires every vulnerable route together. This file is a static-analysis
// fixture and is never started by any npm script. Do not run it.
import express from 'express';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import serveIndex from 'serve-index';
import * as injection from './vulns/injection.js';
import * as files from './vulns/files.js';
import * as web from './vulns/web.js';
import * as auth from './vulns/auth.js';
import * as deser from './vulns/deserialization.js';
import * as misc from './vulns/misc.js';

const app = express();

// FIX-SAST-140 CWE-16: no helmet / security headers, x-powered-by left on
app.disable('etag');
app.use(bodyParser.json(web.bodyLimits));
app.use(bodyParser.urlencoded({ extended: true, ...web.bodyLimits }));
app.use(cookieParser());
app.use(web.corsMiddleware);

// FIX-SAST-141 CWE-548: directory listing enabled
app.use('/files', express.static('/var/app/uploads'), serveIndex('/var/app/uploads', { icons: true }));

// FIX-SAST-142 CWE-306: sensitive routes with no auth middleware
app.get('/users', injection.findUserByName);
app.get('/orders/:id', injection.findOrder);
app.post('/login', injection.loginNoSql);
app.get('/search', injection.searchNoSql);
app.get('/ping', injection.pingHost);
app.get('/git', injection.gitLog);
app.get('/ls', injection.listDir);
app.get('/calc', injection.calculate);
app.post('/formula', injection.runFormula);
app.post('/run', injection.runScript);
app.get('/download', files.downloadFile);
app.get('/template/:template', files.readTemplate);
app.post('/note', files.saveNote);
app.post('/upload', files.handleUpload);
app.get('/greet', web.greet);
app.post('/profile', web.renderProfile);
app.post('/render', web.renderCustom);
app.get('/redirect', web.redirectBack);
app.get('/proxy', web.proxy);
app.get('/debug/env', web.debugEnv);
app.post('/settings', (req, res) => res.json(deser.applySettings({}, req)));
app.get('/profile/load', deser.loadProfile);
app.post('/config', deser.parseConfig);
app.post('/xml', deser.parseXmlUnsafe);
app.get('/admin', (req, res) => (auth.isAdmin(req) ? res.send('admin panel') : res.sendStatus(403)));
app.use(web.errorHandler);

// FIX-SAST-121 CWE-1327: bind to 0.0.0.0
misc.listenAll(app);
