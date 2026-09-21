# tigergate-test-javascript

Security-scanner validation fixture for JavaScript. Deliberately vulnerable across SCA, SAST, secrets, IaC, CI/CD and SBOM.

| | |
|---|---|
| What is planted, and how to score a scan | [EXPECTED_FINDINGS.md](EXPECTED_FINDINGS.md) |
| Why this is safe to keep in a repo | [SECURITY_FIXTURES.md](SECURITY_FIXTURES.md) |
| List every tagged fixture | `npm run fixtures` (`-- --md` or `-- --json` for other formats) |
| Run the (harmless) tests | `npm test` — no install needed |
| Check a username/password against the fixture login | `npm run check-login -- admin password123` |

Layout:

```
src/app.js, secrets.js, vulnerable.js   original minimal fixtures
src/vulns/*.js                          SAST fixtures by class (injection, files, crypto, web, auth, deserialization, regex, misc)
src/server.js                           Express wiring of every vulnerable route — never started
src/safe/safe.js                        NEGATIVE CONTROL: secure equivalents, expect zero findings
public/                                 DOM XSS page + vendored outdated jQuery stub
config/, .env, .npmrc, scripts/         planted (fake) secrets in every common file type
Dockerfile, docker-compose.yml          container misconfigurations
kubernetes/, terraform/, cloudformation/  IaC misconfigurations
.github/workflows/insecure-ci.yml       CI/CD pipeline weaknesses
package.json, package-lock.json         37 vulnerable direct dependencies; SBOM source of truth
expected/npm-audit-baseline.json        npm audit snapshot to diff SCA results against
```
# tigergate-test-javascript
