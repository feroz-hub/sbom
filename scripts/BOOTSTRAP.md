# Optional workstation bootstrap installers

The developer entry point is
[scripts/dev.py](../docs/development/README.md). These existing installers prepare
tools/dependencies for manual or legacy development; they do not install a
complete application stack or approve any production deployment.

Source checked against e62951c2 on 28 October 2026.

## What they do

| Platform | Existing installer | System installation behavior |
| --- | --- | --- |
| macOS / Linux | scripts/bootstrap.sh (Bash) | Can install system tools and use Homebrew or a supported Linux package manager; may add package sources. |
| Windows | scripts/bootstrap.ps1 (PowerShell) | Can use winget/Chocolatey and install tools; PATH refresh may require a new shell. |

They target Python 3.11 and Node 20 prerequisites, create/reuse .venv, install
requirements.txt, run npm ci, and copy missing backend/frontend example files.
They also ensure a local AI encryption key in .env when applicable. Existing
keys are preserved, but the operation can write an existing environment file.
A rerun can reinstall dependencies; “idempotent” does not mean no writes.

Review workstation/package-manager policy before invoking system installation.
For already provisioned Python/Node, existing skip-system interfaces are:

    bash scripts/bootstrap.sh --skip-system

On Windows:

    powershell -File scripts/bootstrap.ps1 -SkipSystem

Skipping system installation still installs dependencies and may write local
configuration. Full dependency compatibility remains to be checked: the locked
Next.js package requires Node >=20.9.0, more specific than the installer's
major-version check.

## What they do not provide

- PostgreSQL provisioning or database-target approval. PostgreSQL is the normal
  application database; SQLite fallback must be explicit and is not the normal
  full-stack default.
- Redis or compatible Mailpit provisioning. Redis is required by the normal
  developer launcher and production BFF/session configuration.
- A complete authenticated configuration. The backend example disables
  authentication while the frontend example is HCL-oriented and enables it;
  copying both unchanged does not make a coherent login flow.
- Production secret management, schema compatibility approval or release
  acceptance.

Choose a [development profile](../docs/development/README.md) next. Use
[configuration guidance](../docs/reference/configuration.md) to understand
precedence, and the [database gate](../docs/DATABASE_BOOTSTRAP_AND_UPGRADE.md)
before any start/bootstrap/upgrade. Do not run a populated pre-UUID target across
revision 100. Existing manual run.py and npm commands start individual services,
not the whole stack.
