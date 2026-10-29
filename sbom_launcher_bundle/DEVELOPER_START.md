# SBOM Analyzer — one-command local developer start

**Bundle installation instructions, not the active repository entry point.**
The current checkout uses [scripts/dev.py](../scripts/dev.py), as documented in
the [developer guide](../docs/development/README.md). The repository root has no
dev.py, and the canonical launcher has no doctor/setup subcommand. The commands
below refer to this enhanced bundle after explicit installation into a complete
checkout; do not treat the bundle directory as a runnable full project.
Profile/platform and database restrictions in the current guides still apply.

## Which file does what?

| File | Purpose | Run directly? |
| --- | --- | --- |
| `dev.py` at repository root | Convenient one-command entry point. Delegates to the real launcher. | **Yes** |
| `scripts/dev.py` | Checks prerequisites, sets up the environment, selects data services, validates/migrates the dev database, starts API, worker, beat, and frontend. | Also works, but not needed for routine use. |
| `scripts/dev_runtime.py` | Tracks exact child process identities, prevents duplicate launchers, and stops only verified owned processes. | No |
| `scripts/dev_greenfield.py` | Runs a *pre-installed* Greenfield UUID profile. Depends on additional `scripts/greenfield_*` modules and private setup. | No |

**Use one terminal in the repository root:**

```bash
python dev.py doctor --profile legacy
python dev.py --profile legacy
```

The second command is long-running: keep the terminal open. When the application is ready, visit:

- Frontend: `https://localhost:13000`
- API: `http://127.0.0.1:18000`
- Mailpit web UI: `http://127.0.0.1:8025`

To inspect or stop the same development application from another terminal:

```bash
python dev.py status --profile legacy
python dev.py stop --profile legacy
```

`restart`, `doctor`, and `--verbose` are also supported. `python dev.py` with no arguments automatically starts whichever profile was selected by the existing launcher rules. To avoid surprises, explicitly select `--profile legacy` for ordinary Native IAM development until your team standardizes profiles.

## What `start` actually does

1. Check the Python version, and the checkout's `requirements.txt`, `alembic.ini`, and frontend package manifests.
2. Create `.venv` if missing and install backend dependencies only when the requirements stamp has changed or essential imports are missing.
3. Choose PostgreSQL and Redis. Prefer a compatible project Docker Compose service where available; otherwise use compatible local services. Keep Redis as the Celery broker.
4. Find or start Mailpit for development email capture. Wait for both SMTP and its HTTP API.
5. Load `.env.dev.local`, create/validate local development secrets, and strictly target the `sbom_analyser_dev` database. Local PostgreSQL may prompt for credentials on first setup.
6. Validate the existing database schema and apply Alembic migrations. **Never substitute a production or test database.**
7. Run `npm ci` when needed, and prepare a self-signed development HTTPS certificate if absent.
8. Start FastAPI/Uvicorn, Celery worker, Celery Beat, and the Next.js frontend. Check readiness; save logs under `.dev-logs/`.
9. Track child processes with `scripts/dev_runtime.py`; on Ctrl+C or `stop`, stop only verified launcher-owned application processes. Database, Redis, and Mailpit services remain running.

The legacy profile uses dedicated ports: PostgreSQL **55439** (Docker) or **5432** (local); Redis **56379** (Docker) or **6379** (local); SMTP **1025**; Mailpit UI **8025**; API **18000**; frontend **13000**.

The Greenfield UUID profile is different: it uses private pre-provisioned state, its own database at `127.0.0.1:56044`, and other `greenfield_*` support modules, which are **not included in the three attachments**. It must be set up explicitly before using `--profile greenfield`.

## Requirements and limitations

- Python **3.11+** is necessary, but Python alone cannot run this full stack. You also need Node.js/npm, the complete SBOM Analyzer source repository, and working data services.
- Docker is **optional** if suitable local services are installed. On Windows without Docker, local PostgreSQL, Redis-compatible service, and Mailpit still need to be available. The launcher does not install operating-system services by itself.
- Local database credentials may need one interactive entry before they can be saved. The script will not guess credentials or silently use a different database.
- `doctor` is a read-only prerequisite check, **not** a guarantee that a database migration or the entire app will run. It does not install packages or start containers.
- Do not commit `.env.dev.local`, `.venv`, `.dev-logs`, `.dev-runtime.*`, `.dev-beat.pid`, certificates containing private keys, or machine-specific settings. Check your existing `.gitignore` before using the bundle.
- A self-signed HTTPS certificate may need to be trusted in a browser by the developer.
- This bundle was checked in isolation. Full end-to-end startup **cannot be validated without your repository, compose services, migrations, and actual console error**.

## If startup fails

1. Rerun `python dev.py doctor --profile legacy`.
2. Run `python dev.py --profile legacy --verbose` to see technical diagnostics. Normal mode now also shows the tail of failed `pip`, `npm`, Alembic, and service logs.
3. Inspect `.dev-logs/api.log`, `.dev-logs/celery-worker.log`, `.dev-logs/celery-beat.log`, or `.dev-logs/frontend.log` as indicated by the failure.
4. Send the exact `[ERROR]` and relevant `[DETAIL]` output to the maintainer. Remove secrets before sharing.

| Symptom | Meaning / action |
| --- | --- |
| Incomplete checkout / missing `requirements.txt` | Ensure `scripts/dev.py` is under your SBOM repository's `scripts/` directory, with manifests at the repository root. |
| Port **55439** occupied | Another service (previously a reconciliation test DB on one machine) owns the port. Do not kill or overwrite it. Use the supported local PostgreSQL provider, or resolve the port mapping deliberately. |
| PostgreSQL credentials rejected | Enter the intended local PostgreSQL role/password. Check `.env.dev.local` and local pgpass; never substitute production credentials. |
| Mailpit readiness timeout | SMTP may start before Mailpit's HTTP API. Confirm both `1025` and `8025` are reachable and inspect container/service logs. |
| Unknown or incomplete database schema | The launcher safely refuses to migrate a database it cannot identify. Inspect it; do not drop/recreate data casually. |
| API, Celery, or frontend exited | Open the indicated `.dev-logs/*.log`; a missing dependency, wrong configuration, or code error usually appears there. |
| Greenfield import error | Extra `greenfield_uuid.py`, `greenfield_https.py`, and `greenfield_migrations.py` files and private setup are required. Use `--profile legacy` if Greenfield was not intended. |

## Installing the bundle into the existing repository

This is a proposed update to **review and merge**, not a complete copy of the SBOM Analyzer application. Compare these files against your current Git branch before replacing anything. Preserve any newer changes in your repository.

```text
sbom/
  dev.py                        # new simple entry point
  scripts/
    __init__.py                 # package marker
    dev.py                      # enhanced copy of the provided dev(1).py
    dev_runtime.py              # provided runtime helper, unchanged
    dev_greenfield.py           # provided Greenfield helper, unchanged
  requirements.txt              # already in your repository
  alembic.ini                   # already in your repository
  frontend/                     # already in your repository
  app/                          # already in your repository
```

Run launcher unit tests from the repository root with `python -m unittest discover -s tests -p test_launcher.py` after copying the included test to a suitable tests folder. The tests do not start services or modify a database.

## What was improved in this bundle

- A root-level `python dev.py` entry point avoids memorizing `scripts/dev.py`.
- An explicit `doctor` command and early checkout/Python checks make common setup mistakes clearer.
- The selected profile is displayed before startup.
- On failure, redacted output from Python package installation, Node package installation, Docker Compose startup, Alembic migrations, and service logs is surfaced even without `--verbose`.
- Critical Celery imports are included in the dependency-presence check.
- Process ownership rules, safe shutdown, dedicated database guardrails, and the existing Greenfield behavior are preserved.
