# Header and content scrolling regression

Run against an existing isolated instance with seeded tenant-admin and platform-admin accounts:

```sh
LAYOUT_E2E_ORIGIN=https://localhost:13500 \
LAYOUT_E2E_USERS_FILE=/absolute/path/to/test-users.json \
npm run test:layout
```

The private users file has `admin` and `platform` entries, each containing `email` and `password`. Use existing test credentials; do not commit them. The admin account must have a selected/default tenant and existing SBOMs with analysis runs. The optional `LAYOUT_E2E_RESULTS` sets the output directory (default `/tmp/sbom-layout-results`). HTTPS certificate verification stays enabled.

The tests sign in and read existing pages. They do not create projects, upload SBOMs, run analyses, download reports, or save settings. Short pages receive a temporary DOM notification and spacer to exercise real wheel scrolling. These fixtures never reach the server. One test inserts a temporary progress row to check automatic height allocation. Desktop and mobile dashboard screenshots show the real page after scrolling.

Coverage includes tenant navigation, platform administration, vulnerabilities, SBOM components/history, analysis findings/report controls, six viewport sizes, sidebar collapse and independent scrolling, mobile drawer navigation, skip-link focus, dialog scroll locking, and changing progress-row height. Report exports are part of analysis-run detail; there is no standalone Reports route.

The checks assert that the header stays at viewport top, main begins below all global rows, the document has no second scrollbar, page titles scroll with content, and sidebar scrolling does not move main. The dialog test also clears the shared body flag to simulate a closed sibling dialog's cleanup; the visible modal must still lock background scrolling. Public sign-in/access routes retain normal document scrolling and remain covered by the AppShell unit tests.
