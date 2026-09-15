// Deliberately catastrophic regular expressions (ReDoS) for SAST validation.

// FIX-SAST-110 CWE-1333: nested quantifier ReDoS
export const EMAIL_RE = /^([a-zA-Z0-9]+)*@([a-zA-Z0-9]+\.)+[a-zA-Z]{2,}$/;

// FIX-SAST-111 CWE-1333: overlapping alternation with unbounded repetition
export const URL_RE = /^(https?:\/\/)?([\w-]+(\.[\w-]+)+)*([\w.,@?^=%&:/~+#-]*)*$/;

// FIX-SAST-112 CWE-1333: classic (a+)+ pattern
export const isRepeated = s => /^(a+)+$/.test(s);

// FIX-SAST-113 CWE-1333: regex built from user input (also CWE-400)
export function matchUser(req) {
  return new RegExp(req.query.pattern).test(req.query.subject);
}

// FIX-SAST-114 CWE-1333: whitespace-trim ReDoS
export const trimSpaces = s => s.replace(/\s+$/, '');

// FIX-SAST-115 CWE-400: unbounded loop driven by user-supplied count
export function repeat(req) {
  let out = '';
  for (let i = 0; i < Number(req.query.count); i++) out += req.query.s;
  return out;
}

// FIX-SAST-116 CWE-400: allocation sized by user input
export const allocate = req => Buffer.allocUnsafe(Number(req.query.size));
