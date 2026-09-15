# Deliberately insecure test fixtures

This repository exists to validate security scanners — SCA, SAST, secret detection, IaC, CI/CD and SBOM
tooling. It deliberately contains outdated dependencies, unsafe code patterns, fake hard-coded credentials
and insecure infrastructure definitions. **Do not deploy, run, or reuse anything in it.**

- The full inventory of planted weaknesses, with scoring guidance, is in [EXPECTED_FINDINGS.md](EXPECTED_FINDINGS.md).
- Every weakness is tagged `FIX-<CATEGORY>-<NNN>` in a comment beside it. `npm run fixtures` lists them.
- `src/safe/safe.js` and `.env.example` are **negative controls** — secure code and placeholder config that a scanner should not flag.

## Safety properties

- No credential in this repo is real. AWS values are Amazon's documented example pair; private keys were generated
  locally for this repo and are used by nothing; every other token has `FIXTURE` in its body. Nothing validates.
- `src/server.js` is never started by any npm script (`npm start` refuses). It exists for static analysis only.
- The Dockerfile, Compose file, Kubernetes manifests, Terraform and CloudFormation are not meant to be applied.
- `npm test` imports only `src/app.js` and `src/safe/safe.js` and needs no dependencies installed.

## Pushing to GitHub

GitHub push protection may block the commit because of the planted tokens. If it does, use the
"it's used in tests" bypass reason — that is literally what they are for.
