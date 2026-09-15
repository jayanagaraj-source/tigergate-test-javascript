# Expected findings

Ground truth for scoring a scanner run against this repository. Every deliberate weakness carries a
`FIX-<CATEGORY>-<NNN>` tag in a comment beside it, so results can be matched by file and line.

Regenerate the tables below with `npm run fixtures -- --md`; the raw list is `npm run fixtures`.

## How to score a scan

1. **Detection rate** per category = tagged fixtures the scanner reported ÷ tagged fixtures in that category.
   A tag counts as detected if the scanner reports *any* finding on that line (±3 lines) or on that resource block.
2. **False-positive rate** = findings in [`src/safe/safe.js`](src/safe/safe.js) or [`.env.example`](.env.example).
   Both are negative controls; a correct scanner reports **nothing** in them.
3. **SCA** is scored against [`expected/npm-audit-baseline.json`](expected/npm-audit-baseline.json)
   (`npm audit --json`, captured 2026-09-15 — advisory counts only grow over time, so treat it as a floor).
4. **SBOM** is scored by component count and metadata against `package-lock.json` (see the SBOM section).

Many fixtures map to several rule IDs in a real scanner, and some rules will flag more than one tag. Score by tag, not by raw finding count.

## Summary

| Category | Tagged fixtures | Primary locations |
|---|---|---|
| SAST | 116 | `src/vulns/*.js`, `src/server.js`, `public/index.html`, `scripts/deploy.sh` |
| Secrets | 10 tags covering ~35 distinct credentials | `.env`, `config/`, `.npmrc`, `scripts/deploy.sh`, `Dockerfile`, k8s/tf/CI files |
| IaC | 66 | `Dockerfile`, `docker-compose.yml`, `kubernetes/`, `terraform/`, `cloudformation/`, `.github/workflows/` |
| SCA | 37 direct deps with advisories (83 packages total) + 3 tagged config fixtures | `package.json`, `package-lock.json`, `.npmrc`, `public/vendor/` |
| Negative controls | 0 expected findings | `src/safe/safe.js`, `.env.example` |

## SCA baseline (from `npm audit`, 2026-09-15)

Totals: **83 vulnerable packages — 18 critical, 40 high, 20 moderate, 5 low.** 37 of the 38 direct dependencies carry an advisory.

| Direct dependency | Pinned | Severity | Headline advisory |
|---|---|---|---|
| axios | 0.21.0 | high | SSRF (CVE-2020-28168), ReDoS |
| body-parser | 1.18.2 | high | DoS via URL encoding (CVE-2024-45590) |
| debug | 2.6.8 | high | ReDoS (CVE-2017-16137) |
| decode-uri-component | 0.2.0 | high | DoS (CVE-2022-38900) |
| dompurify | 2.0.0 | critical | multiple XSS bypasses |
| ejs | 3.1.6 | critical | RCE via render options (CVE-2022-29078) |
| express | 4.16.0 | high | open redirect (CVE-2024-29041), XSS in redirect |
| handlebars | 4.0.11 | critical | prototype pollution → RCE (CVE-2019-19919, CVE-2021-23369) |
| js-yaml | 3.13.0 | high | code execution on load (CVE-2019-... GHSA-8j8c-7jfh-h6hx) |
| jsonwebtoken | 8.5.1 | high | key confusion / insecure defaults (CVE-2022-23529/23539/23540) |
| jsreport-core | 2.0.0 | critical | via transitive; **LGPL license** |
| jszip | 3.2.0 | moderate | prototype pollution, path traversal; **MIT OR GPL-3.0 dual license** |
| left-pad | 1.3.0 | — | **deprecated**, WTFPL license |
| libxmljs | 0.19.7 | critical | type confusion (CVE-2024-34391/34392) — optional dep |
| lodash | 4.17.15 | high | prototype pollution (CVE-2020-8203), ReDoS, command injection in template |
| marked | 0.3.6 | high | XSS, ReDoS |
| minimist | 1.2.0 | critical | prototype pollution (CVE-2020-7598, CVE-2021-44906) |
| mocha (dev) | 6.1.4 | critical | via transitive (minimist etc.) |
| moment | 2.29.1 | high | path traversal (CVE-2022-24785), ReDoS (CVE-2022-31129) |
| mongoose | 5.7.5 | critical | prototype pollution, search injection |
| mysql | 2.17.1 | moderate | SQL injection via `sql` object |
| node-fetch | 2.6.0 | high | size-limit bypass, header leak on redirect (CVE-2022-0235) |
| node-forge | 0.9.0 | high | signature verification bypass (CVE-2022-24771/24772/24773); **BSD OR GPL-2.0** |
| node-serialize | 0.0.4 | critical | RCE via `unserialize` (CVE-2017-5941); **no license field** |
| nodemon (dev) | 1.18.0 | high | via transitive |
| qs | 6.5.2 | high | prototype pollution (CVE-2022-24999) |
| request | 2.88.2 | critical | SSRF (CVE-2023-28155); **deprecated** |
| semver | 5.7.1 | high | ReDoS (CVE-2022-25883) |
| serialize-javascript | 2.1.0 | high | RCE (CVE-2020-7660), XSS |
| serve-index | 1.9.1 | — | pulls in old `mime`/`debug` |
| shelljs | 0.8.4 | high | privilege escalation (CVE-2022-0144) |
| tar | 4.4.10 | critical | arbitrary file write / traversal (CVE-2021-32803, -32804, -37701…) |
| tough-cookie | 4.1.2 | moderate | prototype pollution (CVE-2023-26136) |
| ua-parser-js | 0.7.28 | — | **deprecated** by publisher with ReDoS note (CVE-2022-25927) |
| underscore | 1.12.0 | critical | arbitrary code execution (CVE-2021-23358) |
| validator | 10.11.0 | high | ReDoS in multiple validators |
| vm2 | 3.9.11 | critical | sandbox escape (CVE-2023-29017, -29199, -30547…) |
| ws | 5.2.2 | high | ReDoS in Sec-WebSocket-Protocol (CVE-2021-32640), DoS |
| xml2js | 0.4.23 | moderate | prototype pollution (CVE-2023-0842) |

License-scanning expectations: `jsreport-core` (LGPL), `jszip` (MIT OR GPL-3.0), `node-forge` (BSD-3-Clause OR GPL-2.0),
`left-pad` (WTFPL), `node-serialize` (**no license declared**). Everything else is MIT/ISC/BSD/Apache-2.0.

## SBOM expectations

- `package-lock.json` (lockfileVersion 3) resolves **709** package entries; a CycloneDX/SPDX SBOM should list roughly that many components (exact count depends on whether the root and optional `libxmljs` tree are included).
- Root component metadata: name `tigergate-test-javascript`, version `1.0.0`, license `MIT`, repository URL present.
- `dependencies` (36) vs `devDependencies` (2) vs `optionalDependencies` (1) should be distinguishable by scope.
- Every resolved entry has an `integrity` hash and registry `resolved` URL — an SBOM without hashes is incomplete.
- `public/vendor/jquery-1.12.4.min.js` is a vendored, un-manifested component (FIX-SCA-031). Only header-based detection will find it; a lockfile-only SBOM will miss it. That gap is itself a result worth recording.

## Secrets — what is planted where

All credentials are fake: AWS values are Amazon's documented example pair, private keys were generated locally for this repo and are used nowhere, and every other token has `FIXTURE` embedded in its body. None validate against any provider.

| File | Credential types |
|---|---|
| `.env` | Postgres/Mongo/Redis URLs with passwords, AWS key pair, GitHub PAT, Slack bot token + webhook, Stripe live + test keys, SendGrid, Twilio SID + token, Google API key, OpenAI, Anthropic, Telegram bot, Mailchimp, Heroku, JWT/session secrets, admin password |
| `config/fixture-private-key.pem` | RSA private key (PEM) |
| `config/fixture-ec-key.pem` | EC private key (PEM) |
| `config/fixture_id_ed25519` | OpenSSH private key |
| `config/gcp-service-account.json` | GCP service-account JSON with embedded private key |
| `config/database.yml` | DB password in YAML |
| `config/settings.json` | Azure storage connection string, Azure client secret, Firebase key, SMTP password, HS256 secret + signed JWT, basic-auth URL, Discord webhook |
| `.npmrc` | npm registry auth token |
| `scripts/deploy.sh` | AWS pair, Docker password, DB password on command line |
| `Dockerfile` | AWS pair + DB password in ENV/ARG, npm token written to `.npmrc` |
| `docker-compose.yml` | DB URL, JWT secret, AWS secret in `environment:` |
| `kubernetes/deployment.yaml`, `kubernetes/secret.yaml` | DB password, AWS secret as env; base64 Secret + `stringData` GitHub PAT; DB URL in ConfigMap |
| `terraform/*.tf` | AWS pair in provider block and `locals`, RDS password, Lambda env API key, secrets in EC2 `user_data` |
| `cloudformation/template.yaml` | DB password parameter default, Lambda env Stripe key |
| `.github/workflows/insecure-ci.yml` | npm token + AWS secret in workflow `env:` |
| `public/index.html` | Google Maps key in client JS, JWT + card number in localStorage |
| `src/vulns/auth.js`, `src/vulns/crypto.js`, `src/secrets.js` | hardcoded passwords, JWT secret, API token, AES key |

## Tagged fixtures

### IAC

| ID | Location | Finding |
|---|---|---|
| FIX-IAC-001 | `Dockerfile:2` | mutable "latest" tag, no digest pin |
| FIX-IAC-002 | `Dockerfile:5` | secrets baked into image via ARG/ENV |
| FIX-IAC-003 | `Dockerfile:12` | unpinned package install, apt lists not cleaned, sudo installed |
| FIX-IAC-004 | `Dockerfile:15` | remote script piped into shell, TLS verification off |
| FIX-IAC-005 | `Dockerfile:19` | ADD from a remote URL |
| FIX-IAC-006 | `Dockerfile:23` | whole build context copied (includes .env, .git, keys) |
| FIX-IAC-007 | `Dockerfile:27` | world-writable app dir, SSH enabled, root password set |
| FIX-IAC-008 | `Dockerfile:30` | SSH port and privileged port exposed |
| FIX-IAC-009 | `Dockerfile:33` | no USER instruction — runs as root. No HEALTHCHECK. |
| FIX-IAC-010 | `docker-compose.yml:6` | privileged container with host namespaces |
| FIX-IAC-011 | `docker-compose.yml:11` | dangerous capabilities, no-new-privileges off, seccomp/apparmor disabled |
| FIX-IAC-012 | `docker-compose.yml:16` | docker socket and host root mounted |
| FIX-IAC-013 | `docker-compose.yml:21` | secrets in plaintext environment; port bound on all interfaces |
| FIX-IAC-014 | `docker-compose.yml:31` | unpinned DB image, trust auth, root password in env, data dir world-exposed |
| FIX-IAC-020 | `kubernetes/deployment.yaml:15` | host namespaces shared |
| FIX-IAC-021 | `kubernetes/deployment.yaml:19` | default SA token auto-mounted, no seccomp profile |
| FIX-IAC-022 | `kubernetes/deployment.yaml:24` | mutable tag, always pull not set |
| FIX-IAC-023 | `kubernetes/deployment.yaml:27` | privileged, root, privilege escalation, writable root fs, all caps |
| FIX-IAC-024 | `kubernetes/deployment.yaml:36` | no resource requests/limits, no liveness/readiness probes |
| FIX-IAC-025 | `kubernetes/deployment.yaml:40` | secrets as plain env values instead of secretKeyRef |
| FIX-IAC-026 | `kubernetes/deployment.yaml:51` | hostPath mounts of / and the docker socket |
| FIX-IAC-027 | `kubernetes/deployment.yaml:63` | NodePort / LoadBalancer exposing the pod publicly |
| FIX-IAC-028 | `kubernetes/rbac.yaml:1` | cluster-admin bound to the default service account |
| FIX-IAC-029 | `kubernetes/rbac.yaml:17` | wildcard RBAC role |
| FIX-IAC-030 | `kubernetes/secret.yaml:1` |  |
| FIX-IAC-031 | `kubernetes/secret.yaml:16` | sensitive values in a ConfigMap |
| FIX-IAC-032 | `kubernetes/secret.yaml:25` | Pod with insecure sysctls, hostPath, no seccomp, shareProcessNamespace |
| FIX-IAC-040 | `terraform/network.tf:3` | SSH and RDP open to the world, all-ports egress |
| FIX-IAC-041 | `terraform/network.tf:36` | VPC with no flow logs; default NACL allows everything |
| FIX-IAC-042 | `terraform/network.tf:53` | subnet auto-assigns public IPs |
| FIX-IAC-043 | `terraform/network.tf:60` | classic ELB listener on plain HTTP, no access logs |
| FIX-IAC-044 | `terraform/network.tf:73` | ALB listener on HTTP without redirect, drop_invalid_header_fields off |
| FIX-IAC-045 | `terraform/iam.tf:3` | wildcard actions and resources |
| FIX-IAC-046 | `terraform/iam.tf:20` | IAM user with inline policy and console password, no MFA |
| FIX-IAC-047 | `terraform/iam.tf:35` | weak account password policy |
| FIX-IAC-048 | `terraform/iam.tf:47` | role assumable by any AWS principal |
| FIX-IAC-049 | `terraform/data.tf:3` | RDS publicly accessible, unencrypted, hardcoded password, no backups, no deletion protection |
| FIX-IAC-050 | `terraform/data.tf:22` | S3 bucket — no encryption, versioning, logging; public-read ACL; no MFA delete |
| FIX-IAC-051 | `terraform/data.tf:41` | DynamoDB — no point-in-time recovery, no CMK encryption |
| FIX-IAC-052 | `terraform/data.tf:54` | EBS volume unencrypted |
| FIX-IAC-053 | `terraform/data.tf:61` | SQS / SNS without encryption, SQS policy open to everyone |
| FIX-IAC-054 | `terraform/data.tf:78` | KMS key without rotation, policy open to the account root of any account |
| FIX-IAC-055 | `terraform/data.tf:88` | ElastiCache / Redis without transit or at-rest encryption, no auth token |
| FIX-IAC-056 | `terraform/compute.tf:3` | EC2 — IMDSv1 allowed, public IP, unencrypted root volume, secrets in user_data, no monitoring |
| FIX-IAC-057 | `terraform/compute.tf:27` | Lambda — secrets in env, no tracing, no DLQ, wildcard role, unsigned code |
| FIX-IAC-058 | `terraform/compute.tf:42` | CloudTrail not multi-region, no log validation, no encryption; CloudWatch log group without retention/KMS |
| FIX-IAC-059 | `terraform/compute.tf:55` | EKS with public endpoint, no control-plane logging, no secrets encryption |
| FIX-IAC-060 | `scripts/deploy.sh:11` | piping remote content straight into a shell |
| FIX-IAC-061 | `scripts/deploy.sh:13` | TLS verification disabled on download |
| FIX-IAC-062 | `scripts/deploy.sh:15` | world-writable permissions |
| FIX-IAC-063 | `terraform/compute.tf:67` | Terraform provider configured with static credentials |
| FIX-IAC-064 | `terraform/compute.tf:74` | remote state without encryption or locking |
| FIX-IAC-070 | `cloudformation/template.yaml:5` | password parameter with a default and NoEcho off |
| FIX-IAC-071 | `cloudformation/template.yaml:11` | security group open to the world |
| FIX-IAC-072 | `cloudformation/template.yaml:19` | public, unencrypted bucket without versioning/logging |
| FIX-IAC-073 | `cloudformation/template.yaml:29` | RDS public + unencrypted + plaintext password |
| FIX-IAC-074 | `cloudformation/template.yaml:42` | star-star IAM role |
| FIX-IAC-075 | `cloudformation/template.yaml:60` | Lambda with secret in env, old runtime |
| FIX-IAC-080 | `.github/workflows/insecure-ci.yml:4` | pull_request_target combined with checkout of the PR head (pwn request) |
| FIX-IAC-081 | `.github/workflows/insecure-ci.yml:11` | overly broad token permissions |
| FIX-IAC-082 | `.github/workflows/insecure-ci.yml:23` | actions pinned to mutable refs instead of commit SHAs |
| FIX-IAC-083 | `.github/workflows/insecure-ci.yml:30` | script injection — untrusted event data interpolated into a shell |
| FIX-IAC-084 | `.github/workflows/insecure-ci.yml:36` | secrets echoed / written to artifacts |
| FIX-IAC-085 | `.github/workflows/insecure-ci.yml:44` | remote script piped to shell, sudo, TLS verification off |
| FIX-IAC-086 | `.github/workflows/insecure-ci.yml:47` | security step allowed to fail silently |
| FIX-IAC-087 | `.github/workflows/insecure-ci.yml:52` | self-hosted runner used for untrusted PR code |

### SAST

| ID | Location | Finding |
|---|---|---|
| FIX-SAST-001 | `src/vulns/injection.js:11` | CWE-89: SQL injection via string concatenation |
| FIX-SAST-002 | `src/vulns/injection.js:16` | CWE-89: SQL injection via template literal |
| FIX-SAST-003 | `src/vulns/injection.js:22` | CWE-943: NoSQL injection — user-controlled object passed straight to the query |
| FIX-SAST-004 | `src/vulns/injection.js:28` | CWE-943: NoSQL $where with string interpolation (server-side JS injection) |
| FIX-SAST-005 | `src/vulns/injection.js:34` | CWE-78: OS command injection via exec with interpolated input |
| FIX-SAST-006 | `src/vulns/injection.js:39` | CWE-78: command injection via execSync + concatenation |
| FIX-SAST-007 | `src/vulns/injection.js:45` | CWE-78: spawn with shell: true and user input |
| FIX-SAST-008 | `src/vulns/injection.js:51` | CWE-78: shelljs.exec with user input |
| FIX-SAST-009 | `src/vulns/injection.js:56` | CWE-95: eval of user input |
| FIX-SAST-010 | `src/vulns/injection.js:61` | CWE-95: new Function with user input |
| FIX-SAST-011 | `src/vulns/injection.js:67` | CWE-94: vm.runInNewContext is not a sandbox |
| FIX-SAST-012 | `src/vulns/injection.js:72` | CWE-95: setTimeout with a string argument (implicit eval) |
| FIX-SAST-013 | `src/vulns/injection.js:77` | CWE-117: log injection — raw user input written to logs |
| FIX-SAST-014 | `src/vulns/injection.js:82` | CWE-90: LDAP injection |
| FIX-SAST-020 | `src/vulns/files.js:10` | CWE-22: path traversal — user input joined into a filesystem path |
| FIX-SAST-021 | `src/vulns/files.js:16` | CWE-22: path traversal via readFile with raw user input |
| FIX-SAST-022 | `src/vulns/files.js:21` | CWE-73: arbitrary file write with user-controlled path and content |
| FIX-SAST-023 | `src/vulns/files.js:27` | CWE-22: arbitrary file deletion |
| FIX-SAST-024 | `src/vulns/files.js:33` | CWE-22 (Zip Slip): tar extraction without path validation |
| FIX-SAST-025 | `src/vulns/files.js:38` | CWE-22 (Zip Slip): zip entries written using their own names |
| FIX-SAST-026 | `src/vulns/files.js:46` | CWE-732: world-writable permissions |
| FIX-SAST-027 | `src/vulns/files.js:52` | CWE-377: insecure temporary file — predictable name in shared tmp dir |
| FIX-SAST-028 | `src/vulns/files.js:59` | CWE-367: TOCTOU — check then use |
| FIX-SAST-029 | `src/vulns/files.js:67` | CWE-434: unrestricted upload — extension taken from user, no type check |
| FIX-SAST-030 | `src/vulns/crypto.js:7` | CWE-328: MD5 for password hashing |
| FIX-SAST-031 | `src/vulns/crypto.js:10` | CWE-328: SHA-1 for integrity of security-relevant data |
| FIX-SAST-032 | `src/vulns/crypto.js:13` | CWE-327: DES (broken cipher) |
| FIX-SAST-033 | `src/vulns/crypto.js:19` | CWE-327: AES in ECB mode |
| FIX-SAST-034 | `src/vulns/crypto.js:25` | CWE-329 / CWE-321: hardcoded key and static IV |
| FIX-SAST-035 | `src/vulns/crypto.js:33` | CWE-338: Math.random for security tokens |
| FIX-SAST-036 | `src/vulns/crypto.js:37` | CWE-916: password hashing without salt / with a static salt and low iteration count |
| FIX-SAST-037 | `src/vulns/crypto.js:41` | CWE-326: RSA key too short |
| FIX-SAST-038 | `src/vulns/crypto.js:44` | CWE-295: TLS certificate validation disabled |
| FIX-SAST-039 | `src/vulns/crypto.js:50` | CWE-295: process-wide TLS verification disabled |
| FIX-SAST-040 | `src/vulns/crypto.js:53` | CWE-326: deprecated/weak TLS protocol pinned |
| FIX-SAST-041 | `src/vulns/crypto.js:57` | CWE-327: RC4 via node-forge |
| FIX-SAST-042 | `src/vulns/crypto.js:66` | CWE-208: timing-unsafe comparison of secrets |
| FIX-SAST-050 | `src/vulns/web.js:9` | CWE-79: reflected XSS — unescaped input in HTML response |
| FIX-SAST-051 | `src/vulns/web.js:14` | CWE-79: XSS via res.write with concatenation |
| FIX-SAST-052 | `src/vulns/web.js:20` | CWE-79: XSS through template engine with escaping disabled |
| FIX-SAST-053 | `src/vulns/web.js:26` | CWE-79: Handlebars SafeString bypasses escaping |
| FIX-SAST-054 | `src/vulns/web.js:32` | CWE-79: markdown rendered with sanitisation off |
| FIX-SAST-055 | `src/vulns/web.js:37` | CWE-1336: server-side template injection — user input becomes the template |
| FIX-SAST-056 | `src/vulns/web.js:42` | CWE-601: open redirect |
| FIX-SAST-057 | `src/vulns/web.js:47` | CWE-601: open redirect via Location header |
| FIX-SAST-058 | `src/vulns/web.js:53` | CWE-918: SSRF — user-controlled URL fetched server-side (axios) |
| FIX-SAST-059 | `src/vulns/web.js:59` | CWE-918: SSRF via node-fetch |
| FIX-SAST-060 | `src/vulns/web.js:65` | CWE-918: SSRF via deprecated request lib |
| FIX-SAST-061 | `src/vulns/web.js:70` | CWE-942: permissive CORS — wildcard origin with credentials |
| FIX-SAST-062 | `src/vulns/web.js:77` | CWE-942: CORS reflects the request Origin unconditionally |
| FIX-SAST-063 | `src/vulns/web.js:84` | CWE-614 / CWE-1004: cookie without Secure, HttpOnly, SameSite |
| FIX-SAST-064 | `src/vulns/web.js:91` | CWE-113: HTTP response splitting / header injection |
| FIX-SAST-065 | `src/vulns/web.js:97` | CWE-915: mass assignment — request body spread straight into a model update |
| FIX-SAST-066 | `src/vulns/web.js:103` | CWE-209: stack trace returned to the client |
| FIX-SAST-067 | `src/vulns/web.js:108` | CWE-200: environment / config leak endpoint |
| FIX-SAST-068 | `src/vulns/web.js:113` | CWE-352: CSRF protection explicitly disabled |
| FIX-SAST-069 | `src/vulns/web.js:119` | CWE-400: unbounded request body / no rate limit |
| FIX-SAST-070 | `scripts/deploy.sh:17` | eval of interpolated input |
| FIX-SAST-080 | `src/vulns/auth.js:5` | CWE-798: hardcoded credentials |
| FIX-SAST-081 | `src/vulns/auth.js:15` | CWE-798 / CWE-321: hardcoded JWT signing secret |
| FIX-SAST-082 | `src/vulns/auth.js:19` | CWE-347: JWT decoded without verification |
| FIX-SAST-083 | `src/vulns/auth.js:24` | CWE-347: "none" algorithm accepted |
| FIX-SAST-084 | `src/vulns/auth.js:29` | CWE-347: algorithm not pinned — key confusion (RS256 public key used as HS256 secret) |
| FIX-SAST-085 | `src/vulns/auth.js:34` | CWE-613: token with no expiry |
| FIX-SAST-086 | `src/vulns/auth.js:37` | CWE-521: weak password policy |
| FIX-SAST-087 | `src/vulns/auth.js:40` | CWE-256: passwords stored in plaintext |
| FIX-SAST-088 | `src/vulns/auth.js:45` | CWE-307: no brute-force protection — unlimited login attempts, user enumeration |
| FIX-SAST-089 | `src/vulns/auth.js:53` | CWE-384: session fixation — session id taken from the request |
| FIX-SAST-090 | `src/vulns/auth.js:59` | CWE-285 / CWE-639: IDOR — no ownership check |
| FIX-SAST-091 | `src/vulns/auth.js:64` | CWE-287: authentication bypass via client-controlled header |
| FIX-SAST-092 | `src/vulns/auth.js:69` | CWE-330: predictable password-reset token |
| FIX-SAST-093 | `src/vulns/auth.js:72` | CWE-522: basic-auth credentials embedded in request config |
| FIX-SAST-100 | `src/vulns/deserialization.js:9` | CWE-502: node-serialize unserialize on user input (RCE, CVE-2017-5941) |
| FIX-SAST-101 | `src/vulns/deserialization.js:15` | CWE-502: js-yaml unsafe load |
| FIX-SAST-102 | `src/vulns/deserialization.js:20` | CWE-611: XXE — external entities enabled |
| FIX-SAST-103 | `src/vulns/deserialization.js:26` | CWE-1321: prototype pollution via deep merge of user input (lodash 4.17.15) |
| FIX-SAST-104 | `src/vulns/deserialization.js:33` | CWE-1321: prototype pollution via recursive assign |
| FIX-SAST-105 | `src/vulns/deserialization.js:42` | CWE-1321: dynamic property write from user-controlled key |
| FIX-SAST-106 | `src/vulns/deserialization.js:48` | CWE-94: vm2 used as a sandbox for untrusted code (multiple escape CVEs) |
| FIX-SAST-107 | `src/vulns/deserialization.js:53` | CWE-502: JSON.parse of user input then reviver-less use as constructor args |
| FIX-SAST-108 | `src/vulns/deserialization.js:59` | CWE-1321: xml2js with explicit attrs merged into objects |
| FIX-SAST-110 | `src/vulns/regex.js:3` | CWE-1333: nested quantifier ReDoS |
| FIX-SAST-111 | `src/vulns/regex.js:6` | CWE-1333: overlapping alternation with unbounded repetition |
| FIX-SAST-112 | `src/vulns/regex.js:9` | CWE-1333: classic (a+)+ pattern |
| FIX-SAST-113 | `src/vulns/regex.js:12` | CWE-1333: regex built from user input (also CWE-400) |
| FIX-SAST-114 | `src/vulns/regex.js:17` | CWE-1333: whitespace-trim ReDoS |
| FIX-SAST-115 | `src/vulns/regex.js:20` | CWE-400: unbounded loop driven by user-supplied count |
| FIX-SAST-116 | `src/vulns/regex.js:27` | CWE-400: allocation sized by user input |
| FIX-SAST-120 | `src/vulns/misc.js:7` | CWE-489: debug mode / verbose errors enabled |
| FIX-SAST-121 | `src/server.js:54` | CWE-1327: bind to 0.0.0.0 |
| FIX-SAST-121 | `src/vulns/misc.js:10` | CWE-1327: binding to all interfaces |
| FIX-SAST-122 | `src/vulns/misc.js:13` | CWE-319: cleartext HTTP for sensitive traffic |
| FIX-SAST-123 | `src/vulns/misc.js:17` | CWE-547: hardcoded internal IP addresses |
| FIX-SAST-124 | `src/vulns/misc.js:21` | CWE-532: secrets written to logs |
| FIX-SAST-125 | `src/vulns/misc.js:26` | CWE-250: dropping to root / running privileged |
| FIX-SAST-126 | `src/vulns/misc.js:31` | CWE-1188: insecure default — auth disabled when env var missing |
| FIX-SAST-127 | `src/vulns/misc.js:35` | CWE-704: unchecked type coercion used for authorization |
| FIX-SAST-128 | `src/vulns/misc.js:38` | CWE-770: raw TCP server with no limits |
| FIX-SAST-129 | `src/vulns/misc.js:41` | CWE-829: script loaded from a non-HTTPS CDN in server-rendered HTML |
| FIX-SAST-130 | `src/vulns/misc.js:44` | CWE-843 / bad practice: DNS rebinding-prone host allowlist check |
| FIX-SAST-131 | `src/vulns/misc.js:49` | CWE-676: dangerous deprecated Buffer constructor |
| FIX-SAST-132 | `src/vulns/misc.js:52` | CWE-1104: global error swallowing keeps the process alive after unknown state |
| FIX-SAST-133 | `src/vulns/misc.js:56` | CWE-312: sensitive data stored in cleartext localStorage-equivalent (server cache) |
| FIX-SAST-140 | `src/server.js:16` | CWE-16: no helmet / security headers, x-powered-by left on |
| FIX-SAST-141 | `src/server.js:23` | CWE-548: directory listing enabled |
| FIX-SAST-142 | `src/server.js:26` | CWE-306: sensitive routes with no auth middleware |
| FIX-SAST-150 | `public/index.html:6` | CWE-829: third-party script over plain HTTP, no Subresource Integrity |
| FIX-SAST-151 | `public/index.html:11` | CWE-1021: no CSP / no frame-ancestors, plus inline handlers |
| FIX-SAST-152 | `public/index.html:17` | CWE-79 DOM XSS: location.hash -> innerHTML |
| FIX-SAST-153 | `public/index.html:21` | CWE-79 DOM XSS: document.write with URL data |
| FIX-SAST-154 | `public/index.html:23` | CWE-95: eval of URL data |
| FIX-SAST-155 | `public/index.html:25` | CWE-601: DOM open redirect |
| FIX-SAST-156 | `public/index.html:27` | CWE-346: postMessage without origin check + wildcard target |
| FIX-SAST-157 | `public/index.html:30` | CWE-79: jQuery html() / $() with user input |
| FIX-SAST-158 | `public/index.html:33` | CWE-922: sensitive data in localStorage |
| FIX-SAST-159 | `public/index.html:38` | CWE-1004: cookie set without flags from JS |

### SCA

| ID | Location | Finding |
|---|---|---|
| FIX-SCA-030 | `.npmrc:3` | package integrity / audit checks disabled. |
| FIX-SCA-031 | `public/index.html:9` | vendored, outdated jQuery (retire.js-style detection) |
| FIX-SCA-031 | `public/vendor/jquery-1.12.4.min.js:2` | stub of an outdated vendored library. Only the version banner is real; |

### SEC

| ID | Location | Finding |
|---|---|---|
| FIX-SEC-001..009 | `.env:1` | — committed .env with fake credentials for secret-scanner validation. |
| FIX-SEC-010 | `config/gcp-service-account.json:2` | fake GCP service-account key file (private key generated locally, never used)", |
| FIX-SEC-011 | `config/database.yml:1` | plaintext DB credentials in YAML config. |
| FIX-SEC-012..016 | `config/settings.json:2` | assorted provider credentials in a JSON config", |
| FIX-SEC-017 | `scripts/deploy.sh:5` | credentials exported in a shell script |
| FIX-SEC-018 | `scripts/deploy.sh:19` | password on the command line (visible in process list / history) |
| FIX-SEC-019 | `public/index.html:36` | API key in client-side JS |
| FIX-SEC-020 | `.npmrc:1` | npm registry auth token committed to source. |
| FIX-SEC-021 | `kubernetes/secret.yaml:1` | Secret committed to source with base64 (not encryption) values |
| FIX-SEC-022 | `.github/workflows/insecure-ci.yml:15` | secret hardcoded in workflow env |
