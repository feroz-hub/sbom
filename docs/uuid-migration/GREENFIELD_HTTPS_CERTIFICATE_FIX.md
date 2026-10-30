# Greenfield local HTTPS trust fix

Date: 2026-10-19. Scope: the isolated Greenfield UUID development environment only.

**GREENFIELD_HTTPS_TRUST_FIXED_AND_CHROME_VERIFIED**

## Root cause and actual served certificate

The running Next.js supervisor (PID34901) explicitly used `~/.sbom-greenfield-uuid/cert.pem` and `cert-key.pem`. Its OpenSSL-generated leaf was self-signed and untrusted. Both localhost and 127.0.0.1 served the same original fingerprint over TLS1.3. The private key matched the certificate's public key and had mode0600; the failure was certificate authority trust, not a mismatched key or authentication configuration.

macOS `security verify-cert` returned `CSSMERR_TP_NOT_TRUSTED`. Default system curl failed with error60 / verify18 (`self signed certificate`). The previous Playwright configurations used `ignoreHTTPSErrors: true`, which verified application login while bypassing certificate trust. Those historical login results did not establish normal Chrome trust. Proceeding through an interstitial did not install a trusted issuing CA.

The older `frontend/certificates/localhost.pem` was a different self-signed certificate explicitly accepted by macOS (fingerprint `d3434cf55bfffe968d2088d48ee36f91ce7b8f6326ce9b71a4d5cffe62fd204d`). It was not the Greenfield certificate actually served. It also lacked the IPv6 SAN. Its key/files were left unchanged rather than shared across environments.

| Property | Original served leaf | Final served leaf |
|---|---|---|
| Certificate SHA256 | `b6c898656fddd22dd16bcc2242f2fb1c6d78be22b679aa6bed6ecdce9a7b4a3f` | `6a29d683969dc0358919b2fa4f73bff175665c3f44d80e710d6014f45c7b75b4` |
| Subject | CN=localhost | O=mkcert development certificate; OU=local developer identity |
| Issuer | CN=localhost (self-signed) | Existing mkcert development CA |
| SANs | localhost,127.0.0.1 | localhost,127.0.0.1,::1 |
| Validity (UTC) | 2026-10-19 12:16:05 → 2026-11-18 12:16:05 | 2026-10-19 14:44:58 → 2029-01-19 14:44:58 |
| macOS trust / system curl | Rejected / error60 | Accepted / HTTP200, verify0 |
| Leaf private-key mode | 0600 | 0600 |

The final leaf's full issuer is `CN=mkcert ferozebasha@Ferozes-MacBook-Air.local,OU=ferozebasha@Ferozes-MacBook-Air.local,O=mkcert development CA`. Both loopback names were freshly checked against the on-disk DER fingerprint after reload. The certificate includes ::1, but this task did not add an IPv6 listener; Next remains bound to127.0.0.1.

## Trust-store decision and change

**No trust-store change was required or performed. No new root CA was installed.**

mkcert1.4.4 was already installed. The existing CA at `~/Library/Application Support/mkcert/rootCA.pem` was already present in `/Library/Keychains/System.keychain`, and native trust verification passed. Its SHA256 is `aeec90ab9f18d69623813c9e03cc141d4e40768535e0e08bf82d2d8e82411639`; expiry2036-03-03. The CA identity/fingerprint remained unchanged. Only a development server leaf was issued, using this existing CA. No CA private key was printed, copied or added to the repository. No `mkcert -install`, Keychain import, `security add-trusted-cert`, sudo, NSS change or Chrome trust override was run.

The prior Greenfield TLS pair is retained in a private `https-previous-*` directory beneath the existing0700 state directory. New leaf/key files are0600. Application passwords, signing keys and session encryption keys were not replaced.

mkcert's documented workflow separates local CA trust from server certificate configuration; issuing a certificate alone does not configure Next.js. Chrome also considers locally configured trust anchors. References: [mkcert documentation](https://github.com/FiloSottile/mkcert), [Chrome Root Store FAQ](https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/chrome_root_store/faq.md).

## Implementation and recurrence prevention

- Added `scripts/dev.py`: private-file/symlink/hardlink/ownership checks; exact three-name SAN coverage; key matching; CA signature verification; seven-day renewal threshold; native macOS trust verification; a clean subprocess environment; and system curl endpoint verification. It reuses valid material and preserves prior material when replacement is necessary. It never installs a CA or changes trust automatically. Missing/untrusted mkcert CA produces an explicit operator-confirmation diagnostic before issuance or application readiness.
- Updated `scripts/dev.py`: removed the ad-hoc self-signed OpenSSL fallback. Fresh setup checks HTTPS prerequisites before Docker provisioning. Start uses the validated leaf/key. Python's readiness client trusts the issuing CA only after native trust verification, and system curl must independently verify the served endpoint before readiness is reported. Python loading that approved public CA is separate from, and does not replace, macOS/Chrome trust verification.
- Updated `scripts/dev.py` and the Greenfield branch of `scripts/dev.py`: trust validation runs before starting stopped data services; `--check` verifies trust without leaf generation, application password access or service startup. Safe actionable TLS diagnostics reach the developer.
- Updated both Greenfield Playwright configurations: installed Google Chrome (`channel: chrome`) with `ignoreHTTPSErrors: false`. No certificate-bypass flags are added.
- Added `tests/test_dev_greenfield.py`, adjusted mocked launcher coverage, added `python scripts/dev.py doctor --profile greenfield`, and updated README and Greenfield acceptance documentation. The legacy launcher and production certificate management remain separate.

Subsequent `python3 scripts/dev.py start` uses the same stable private certificate paths. A live reuse check confirmed unchanged leaf bytes and key/cert inodes when preparing the already-valid certificate again. Renewal occurs only when needed, with system trust required again. “Permanent” here means persistent trusted local configuration and controlled renewal, not an immortal certificate.

## Frontend-only reload and preservation

Next.js16.3.4's installed source confirms that changing next.config.mjs restarts its server child while retaining the CLI supervisor. After validating the new TLS pair, a comment-only change to the isolated private frontend workspace configuration triggered that supported reload. No tracked application configuration semantics changed. The Next server reported its restart and readiness in477ms. The first immediate curl raced ahead of that asynchronous reload and still saw the old self-signed leaf; it is retained as a failed pre-reload observation, not acceptance evidence. Subsequent native trust/curl/browser checks served the new leaf.

API PID34900, Celery worker PID34899 and frontend supervisor PID34901 were retained. Only the frontend server child restarted. The same PostgreSQL, Redis and Mailpit containers remained running with their original IDs/start timestamps and restart count0. No direct PostgreSQL diagnostic/bootstrap connection, migration, schema/role/grant change, data recreation or Docker lifecycle operation was performed for this certificate task. Normal browser login/logout generated their expected application audit/session activity.

## Actual verification

| Check | Actual result |
|---|---|
| Native macOS leaf verification for localhost | PASS |
| System curl, no curlrc, no `-k`, no custom CA override | localhost and127.0.0.1: HTTP200 / verify0 |
| Served leaf fingerprint | Matches intended final leaf for localhost and127.0.0.1 |
| Installed Google Chrome155.0.8059.84, headed fresh context | PASS with `ignoreHTTPSErrors: false` |
| Chrome certificate bypasses | None; process arguments checked for forbidden certificate/local-origin bypass flags |
| Chrome TLS issuer/protocol | Existing mkcert CA / TLS1.3 |
| Native Admin browser journey | Login200; Olympus selection; Dashboard; refresh retained session; logout200; cookie removed; protected page returned to sign-in and API refused401 |
| Cookie properties | Secure,HttpOnly,SameSite=Lax,Path=/ preserved |
| Browser page errors | None in the successful headed journey |
| Offline certificate/launcher/lifecycle/setup regressions | **186 PASS, 0 FAIL, 0 SKIP**, final source; 6.33seconds |
| Ruff lint/format, AST, focused frontend-config lint, whitespace | PASS |
| Standard launcher `--check`; `python scripts/dev.py doctor --profile greenfield` | PASS with system trust enforced |

The in-app browser backend was unavailable, so verification used the actual installed Google Chrome application via Playwright, in a separate temporary profile. It did not reuse an unsafe exception, disable verification, change the operator's existing Chrome profile or restart unrelated Chrome windows. The strict installed-Chrome Native Login suite initially completed **12 PASS / 1 FAIL**. All role logins, tenant selection/refresh, denial, logout and initial-access cases passed. The expiry test collided with the application's automatic redirect (`page.reload: net::ERR_ABORTED`). Waiting only for navigation commit still reproduced the race in a focused run. The test now waits for the actual reauthentication screen before refreshing it, and additionally asserts that the session endpoint reports authenticated=false. It catches no network/TLS errors, changes no application behavior and retains the signed-out UI/session requirements. That focused rerun passed **1/1** in19.2seconds. Thus all13 distinct strict-Chrome scenarios have passing evidence across the suite/focused rerun; this is not represented as a single clean13-case run. Both initial failures remain in the evidence logs.

One initial offline test run produced182PASS/1FAIL: a bad-signature test raised cryptography's `InvalidSignature` directly. The verifier was already rejecting the signature; it now normalizes this into the explicit trust diagnostic, and subsequent complete tests passed. That initial failure log is preserved.

## Reproduce and fresh developer setup

```sh
# Existing installed Greenfield stack:
python3 scripts/dev.py --check
python scripts/dev.py doctor --profile greenfield
python3 scripts/dev.py start  # only if the instance is stopped

# Explicit certificate preparation: leaf only, trusted CA must already exist.
.venv/bin/python scripts/dev.py doctor --profile greenfield
.venv/bin/python scripts/dev.py doctor --profile greenfield

# Strict Chrome regression (requires installed Google Chrome):
cd frontend/e2e
node node_modules/@playwright/test/cli.js test --config greenfield-login.config.ts
```

On a fresh Mac, install mkcert as a development dependency first. If no trusted CA exists, **stop and obtain explicit operator confirmation before running `mkcert -install` or changing Keychain trust**. Review the CA identity and local root-key handling; never share its private key. The application will not perform that trust change. After the operator independently establishes trust, prepare the leaf and start the application normally.

Open **https://localhost:13000/native-sign-in** and reload any old interstitial. No unsafe Proceed action is needed. Use the `admin` credential from the private users.json (not a guessed/default password), choose Olympus if requested, and confirm Dashboard. Do not paste passwords into chat or logs.

The current native trust adapter is explicitly macOS-only. Another OS needs an independently verified native trust adapter; it fails closed rather than claiming browser readiness. Firefox/NSS, mobile devices, another machine and production TLS were not changed or certified. Each device has its own trust store. A Chrome policy/profile that explicitly overrides local CA trust may need its own operator review; the installed normal Chrome-compatible context on this Mac passed without bypasses. Native trust output may mention missing public Certificate Transparency SCTs for the local CA; native verification still returns success, and Chrome accepted this local trust anchor. That is distinct from the original authority-invalid interstitial.

Sanitized evidence: `~/.sbom-greenfield-uuid/https-diagnostic/` (0700), containing original/final public certificate metadata, reload/process/container preservation, reuse check, Chrome TLS/login outcome, source/test results and the initial failed observations. No private key, password, token, session-cookie value or connection string is included.

## Evidence and source preservation

Private evidence files include `original-certificate.json`, `final-certificate.json`, `reload-before.json`, `reuse-check.json`, `curl-verification.json`, `chrome-trust-result.json`, `chrome-login-suite.log`, `chrome-expiry-focused.log`, `chrome-expiry-stable.log`, `offline-tests.log`, `offline-final-source.log`, and `frontend-lint-last.log`. `acceptance-summary.json` records final public/source fingerprints and result counts. All evidence is sanitized; the actual six synthetic passwords were checked in memory against this task's evidence before completion and were absent. No private key contents or digest was logged.

Branch/HEAD and the dirty worktree were preserved. No commit, push, production configuration change or protected database/resource change was made. No remaining operator trust-store action is needed on this Mac. An already-open warning page may need a normal reload of the URL to observe the replacement certificate; unsafe Proceed or browser security flags are unnecessary.
