// Deliberately unsafe deserialization / parsing fixtures for SAST validation.
import serialize from 'node-serialize';
import yaml from 'js-yaml';
import xml2js from 'xml2js';
import _ from 'lodash';
import { VM } from 'vm2';
import { parseXml } from 'libxmljs';

// FIX-SAST-100 CWE-502: node-serialize unserialize on user input (RCE, CVE-2017-5941)
export function loadProfile(req, res) {
  const profile = serialize.unserialize(Buffer.from(req.cookies.profile, 'base64').toString());
  res.json(profile);
}

// FIX-SAST-101 CWE-502: js-yaml unsafe load
export function parseConfig(req, res) {
  res.json(yaml.load(req.body.yaml, { schema: yaml.DEFAULT_FULL_SCHEMA }));
}

// FIX-SAST-102 CWE-611: XXE — external entities enabled
export function parseXmlUnsafe(req, res) {
  const doc = parseXml(req.body.xml, { noent: true, dtdload: true, noblanks: true });
  res.send(doc.toString());
}

// FIX-SAST-103 CWE-1321: prototype pollution via deep merge of user input (lodash 4.17.15)
export function applySettings(current, req) {
  return _.merge(current, req.body);
}
export const withDefaults = req => _.defaultsDeep({}, req.body, { theme: 'light' });
export const zipped = req => _.zipObjectDeep(req.body.paths, req.body.values);

// FIX-SAST-104 CWE-1321: prototype pollution via recursive assign
export function deepAssign(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object') target[key] = deepAssign(target[key] || {}, source[key]);
    else target[key] = source[key];
  }
  return target;
}

// FIX-SAST-105 CWE-1321: dynamic property write from user-controlled key
export function setPref(prefs, req) {
  prefs[req.body.key] = req.body.value;
  return prefs;
}

// FIX-SAST-106 CWE-94: vm2 used as a sandbox for untrusted code (multiple escape CVEs)
export function runUntrusted(code) {
  return new VM({ timeout: 1000, sandbox: {} }).run(code);
}

// FIX-SAST-107 CWE-502: JSON.parse of user input then reviver-less use as constructor args
export function hydrate(req) {
  const obj = JSON.parse(req.body.payload);
  return Object.assign(Object.create(null), obj, { __proto__: obj.proto });
}

// FIX-SAST-108 CWE-1321: xml2js with explicit attrs merged into objects
export function parseXmlToObject(req, res) {
  xml2js.parseString(req.body.xml, { explicitArray: false, mergeAttrs: true }, (err, result) => res.json(result));
}
