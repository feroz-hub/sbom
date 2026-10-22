"""Run an already installed UUID development stack through dev.py's owned lifecycle.

Start resumes only verified existing containers, then checks the schema before
launching applications. Each supported next-only UUID upgrade requires explicit
interactive confirmation and a verified backup. Never bootstraps or seeds.
"""

from __future__ import annotations

import json
import subprocess
import time

if __package__:
    from . import greenfield_https as https
    from . import greenfield_migrations as migrations
    from . import greenfield_uuid as stack
else:
    import greenfield_uuid as stack

    from scripts import greenfield_https as https
    from scripts import greenfield_migrations as migrations


def inventory():
    stack.verify_resources()
    identities = json.loads(stack.read_private("docker-identities.json"))
    return json.loads(subprocess.check_output(stack.DOCKER + ["inspect", *identities.values()], text=True))


def start(args, runtime):
    # Refuse incomplete installations rather than falling back to another DB
    # or generating new keys during ordinary start/check.
    for filename in ("environment.json", "runtime-password", "setup-password"):
        path = stack.STATE / filename
        if not path.is_file() or path.is_symlink():
            raise RuntimeError("Greenfield setup is incomplete; run make greenfield-setup explicitly")
    https.ensure_certificate(stack.STATE, prepare=not args.check)
    observed = inventory()
    print("Greenfield UUID: sbom_greenfield_uuid at 127.0.0.1:56044", flush=True)
    if args.check:
        for item in observed:
            print(item["Name"].lstrip("/"), "running=" + str(item["State"]["Running"]))
        print("HTTPS trust verified. No services started, application passwords read, or database changes made.")
        return
    if runtime is None:
        raise RuntimeError("Greenfield start requires the dev.py ownership registry")
    runtime.check_stop()
    stopped = [item["Id"] for item in observed if not item["State"]["Running"]]
    if stopped:
        subprocess.run(stack.DOCKER + ["start", *stopped], check=True, capture_output=True)
    deadline = time.monotonic() + 60
    while True:
        runtime.check_stop()
        observed = inventory()
        healthy = all(item["State"]["Running"] for item in observed) and all(
            item["State"].get("Health", {}).get("Status") == "healthy"
            for item in observed
            if item["Name"].endswith("-postgres-1")
        )
        if healthy:
            break
        if time.monotonic() >= deadline:
            raise RuntimeError("Greenfield data services did not become healthy; resources retained")
        time.sleep(0.5)
    migrations.ensure_current()
    runtime.check_stop()
    processes = stack.start_services(runtime=runtime)
    print("Greenfield UUID ready. Logs: ~/.sbom-greenfield-uuid/*.log", flush=True)
    print("Press Ctrl+C to stop the application; data services remain running.", flush=True)
    while True:
        runtime.refresh()
        if any(process.poll() is not None for process in processes.values()):
            raise RuntimeError("A greenfield application service exited; inspect its private log")
        time.sleep(0.5)


def status(runtime):
    state = runtime.load() or {}
    print("Greenfield UUID development status")
    for name in ("API", "Frontend", "Celery worker"):
        record = state.get("services", {}).get(name)
        print(name, runtime.service_status(record) if record else "STOPPED")
    for item in inventory():
        print(item["Name"].lstrip("/"), "RUNNING" if item["State"]["Running"] else "STOPPED")
    print("Database: sbom_greenfield_uuid, 127.0.0.1:56044")
    print("Frontend: https://localhost:13000; API: http://127.0.0.1:18000; Mail: http://127.0.0.1:8026")
