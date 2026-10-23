# Analysis UI verification evidence

See [the implementation report](../analysis-ui-redesign.md) for the root cause,
file inventory, data limitations and test results.

`consolidated-before.png` comes from the existing authenticated snapshot
application. All `after` and dark-theme screenshots use the actual current
frontend with deterministic Playwright API fixtures. These images do not claim
live external vulnerability-provider or worker acceptance.

The browser suite is independent of the existing repair/UAT configuration:

```sh
# Terminal 1, from frontend; use a working Node runtime on PATH.
NEXT_PUBLIC_AUTH_ENABLED=true node node_modules/next/dist/bin/next dev \
  --webpack --hostname localhost --port 13001 --experimental-https \
  --experimental-https-key certificates/localhost-key.pem \
  --experimental-https-cert certificates/localhost.pem

# Terminal 2, from frontend/e2e.
node node_modules/@playwright/test/cli.js test --config analysis.config.ts
```

Use an existing trusted development certificate. The suite sets
`ignoreHTTPSErrors: false`, supplies a fixture-only browser cookie, intercepts
all API calls, and never submits real credentials or runs a production scan.
Screenshots are refreshed in this folder. Transient runner output goes to
`/tmp/sbom-analysis-ui-browser`.

Backend tests require an explicitly disposable PostgreSQL database and run the
repository's migration/test fixtures there. Never point `TEST_DATABASE_URL`
or `TEST_POSTGRES_DATABASE_URL` at an existing application database.
