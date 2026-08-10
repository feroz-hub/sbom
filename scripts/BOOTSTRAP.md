# Local-machine bootstrap

Two installer scripts that bring a fresh machine to a working dev state for the SBOM Analyzer.
They install **Python 3.11** and **Node.js 20**, set up the backend venv with `requirements.txt`,
run `npm ci` for the frontend, and copy `.env` / `.env.local` from the example files if missing.

Both scripts are idempotent — re-running them only does the work that hasn't been done yet.

## Which script to run

| OS | Script | Run from |
|---|---|---|
| macOS | `scripts/bootstrap.sh` | Terminal (bash or zsh) |
| Linux | `scripts/bootstrap.sh` | Any POSIX shell |
| Windows | `scripts/bootstrap.ps1` | PowerShell (5.1+ or 7+) |

## macOS / Linux

```bash
cd <repo>
chmod +x scripts/bootstrap.sh        # one-time
./scripts/bootstrap.sh
```

The script auto-detects the OS and uses the right package manager:

- **macOS** — Homebrew. Installs it first if missing.
- **Debian / Ubuntu / Mint** — `apt-get`. Adds the deadsnakes PPA only if `python3.11` isn't already in the repos.
- **Fedora / RHEL / Rocky / Alma / CentOS** — `dnf` (or `yum`).
- **Arch / Manjaro** — `pacman`.
- **openSUSE** — `zypper`.
- **Alpine** — `apk`.

For Node 20 on apt/dnf-based distros it pulls the official NodeSource setup
script (`setup_20.x`) so you don't end up with a stale distro Node.

If you already have Python 3.11 and Node 20 from another source (asdf, nvm,
pyenv, Volta, your corporate image, etc.), skip the system step:

```bash
./scripts/bootstrap.sh --skip-system
```

## Windows

Open PowerShell (Windows Terminal is fine) and run:

```powershell
cd <repo>
# Allow this single script to run, just for this session:
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\bootstrap.ps1
```

The script prefers **winget** (built into Windows 10 21H2+ and Windows 11). If
winget is missing it falls back to **Chocolatey**, installing Chocolatey itself
if neither is present.

If you have Python/Node already:

```powershell
.\scripts\bootstrap.ps1 -SkipSystem
```

> **Tip:** if the script installs Python or Node for the first time, you may
> need to close and reopen PowerShell so the new tools land on `PATH`, then
> re-run with `-SkipSystem` to finish the venv + npm steps.

## What gets installed

| Component | macOS | Debian/Ubuntu | Fedora/RHEL | Arch | Windows |
|---|---|---|---|---|---|
| Python 3.11 | `python@3.11` | `python3.11 python3.11-venv python3.11-dev` | `python3.11 python3.11-devel` | `python` | `Python.Python.3.11` |
| Node 20 | `node@20` | NodeSource `nodejs` | NodeSource `nodejs` | `nodejs npm` | `OpenJS.NodeJS.LTS` |
| Build toolchain | (via Xcode CLT) | `build-essential libxml2-dev libxslt1-dev libssl-dev libffi-dev libpq-dev` | `gcc gcc-c++ make libxml2-devel libxslt-devel openssl-devel libffi-devel libpq-devel` | `base-devel libxml2 libxslt openssl libffi postgresql-libs` | (Windows wheels) |

The build toolchain on Linux is only there in case `lxml`, `cryptography`, or
`psycopg` need to compile from source — current binary wheels cover most
distros, so usually nothing is built.

## What the scripts do NOT install

- **Redis** — only needed for Celery-backed background scans. Default dev
  runs scans synchronously inside the API process, so this is optional.
- **PostgreSQL** — SQLite is the dev default. Install Postgres only if you're
  validating the production path locally.
- **API keys** — `NVD_API_KEY`, `GITHUB_TOKEN`, `VULNDB_API_KEY`, and any AI
  provider keys are all optional. The script seeds `.env` from `.env.example`;
  fill in keys later as needed.

## After it finishes

```bash
# Backend
source .venv/bin/activate      # macOS/Linux
# or
.\.venv\Scripts\Activate.ps1   # Windows

python run.py                  # http://localhost:8000

# Frontend (separate terminal)
cd frontend
npm run dev                    # http://localhost:3000
```

## Troubleshooting

- **Script says Python/Node aren't on PATH after install.** Open a new shell so
  it picks up the updated `PATH`, then re-run with `--skip-system` /
  `-SkipSystem` to finish the venv + npm steps.
- **Older Ubuntu (20.04) doesn't have `python3.11`.** The script adds the
  deadsnakes PPA automatically. If your corporate apt mirror blocks PPAs,
  install Python 3.11 by hand (e.g. via `pyenv`) and pass `--skip-system`.
- **Behind a corporate proxy.** Set `HTTPS_PROXY` / `HTTP_PROXY` before running.
  pip, npm, apt, dnf, and winget all honour those vars.
- **`pip install` is slow or compiles wheels from source.** Make sure pip is
  current: `python -m pip install --upgrade pip`. Old pips fall back to source
  builds because they can't read modern wheel tags.
