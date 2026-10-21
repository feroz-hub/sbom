# Browser preparation diagnostics

Some repeated dashboard and six-role preparation attempts timed out or redirected to Native sign-in while backend regressions and dev compilation were active. These are retained in browser-dashboard-final*.log, browser-dashboard*.json and browser-kev-final.json. They are not accepted positive executions.

The Native/Entra BFF session check in frontend/src/app/api/auth/session/route.ts uses a five-second backend timeout and returns authenticated=false with HTTP 503 on transport failure. AuthProvider treats an unsuccessful session check as unauthenticated. This is a plausible explanation under observed local load, not a proven diagnosis for every failed navigation. No authentication guard or timeout was relaxed. Final accepted runs, if completed, are separately indexed.

A stopped isolated frontend was restarted using its existing trusted certificate and private workspace; no global TLS setting changed. Backend test fixtures use dedicated databases. Successful module fixtures warm session/context read routes before browser navigation; no browser cookie or bearer value is recorded.
