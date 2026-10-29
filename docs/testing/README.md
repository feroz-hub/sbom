# Testing and static checks

Scope: existing commands and their limits, checked against e62951c2 on
28 October 2026. No application tests or builds were run for documentation
standardisation.

## Resource safety first

[tests/conftest.py](../../tests/conftest.py) resolves a PostgreSQL test target,
can bootstrap it, truncate application tables and reset sequences. It has a
default target if none is supplied. Explicitly identify and authorize a disposable
test database before running pytest, including collection that imports fixtures.
A database name containing “test” is not sufficient operator authorization.

Never run these examples against the application or production database.
Supply credentials through protected process configuration, not shell history
or committed examples. Provider/browser acceptance can also make external calls
or create records; use its isolated scenario instructions.

## Backend

Install the project's dependencies and development tools in an isolated Python
environment. requirements.txt includes testing packages; pyproject.toml also
declares development extras. The current Docker installation resolves the
project manifest independently. Installation/build parity is unverified here.

After configuring the disposable test target, from the repository root:

    python -m pytest -q
    python -m pytest tests/validation/ -m "not bench"
    python -m pytest -m integration
    python -m pytest -m bench

[pytest.ini](../../pytest.ini) excludes integration and bench in the default
command. Explicit marker selection is required for those suites; the validation
example includes integration-marked validation tests but excludes benchmarks.
There is no registered schema marker. These are different coverage claims,
not interchangeable “full green” commands.

Focused suites should match the changed behavior, such as launcher ownership,
public UUID contracts, IAM/tenant isolation, VEX/metrics or report storage.
Historical migration tests need their own supported isolated fixtures.

Static Python tools, when installed:

    python -m ruff check app scripts tests
    python -m mypy app

Keep scanner scope explicit. Historical source snapshots under docs are evidence,
not a second active application; do not use a broad scan to silently redefine
either scope or the existing failure baseline.

## Frontend unit and build checks

From frontend, with public build settings and BFF configuration selected:

    npm ci
    npm run lint
    npx tsc --noEmit
    npm test
    npm run build

These commands exist in the
[frontend manifest](../../frontend/package.json). cross-env is already a declared
development dependency; do not add it ad hoc to work around an incomplete install.
Build and typecheck can generate local files. Passing Vitest does not prove
browser, provider, physical-device or assistive-technology acceptance.

## Browser scenarios

[frontend/e2e](../../frontend/e2e) has a separate package and scenario configs.
The default [Playwright config](../../frontend/e2e/playwright.config.ts) requires
REPAIR_E2E_MANIFEST produced by an isolated repair scenario. Other configs have
different targets and prerequisites; inspect the selected config before invoking
its commands. Do not run all browser configs against the populated developer app.

See the [manual smoke plan](../../Testing.md) and
[KEV checklist](../kev_testing_checklist.md) for controlled checks.
Record exact source revision, target, profile, commands and configuration mode;
separate passes, failures, exclusions, blocked prerequisites and unverified live
acceptance. Old UAT logs are historical evidence, not a current test baseline.
