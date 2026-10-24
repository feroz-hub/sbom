"""Explicit local metadata and future secret providers; import does no IO.

No PostgreSQL driver imported here. Mounted secret bytes are read only after
live authority; current preparation uses snapshot()/credential stat ONLY.
"""

from __future__ import annotations

import hmac
import json
import os
import re
import stat
import subprocess
from pathlib import Path

from security import SECRET, credential_metadata, private_bytes, require, sha, unique

DOCKER = "/usr/local/bin/docker"
SOCKET = "/Users/ferozebasha/.docker/run/docker.sock"
DAEMON = "1f8c7fe5-5972-4adc-8d6e-363a38572be1"
CONTAINER = "964fe491cf9e12f6f9cf8125f5352e301d85f0fc1a0b05142cda6393c6d9152c"
IMAGE = "sha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54"
NETWORK = "sbom-uuid-w2-f_f_access"
NETWORK_ID = "5347909a2fb95db230d562557e5154cf623ccb613286eca309134da6e9122447"
VOLUME = "sbom-uuid-w2-f_f_pgdata"


# Server-side projection avoids ever retrieving Config.Env or healthcheck output.
CONTAINER_FORMAT = (
    '{"Id":{{json .Id}},"Name":{{json .Name}},"Image":{{json .Image}},'
    '"Created":{{json .Created}},"RestartCount":{{json .RestartCount}},'
    '"Config":{"Labels":{{json .Config.Labels}}},"Mounts":{{json .Mounts}},'
    '"State":{"Status":{{json .State.Status}},"Running":{{json .State.Running}},'
    '"Paused":{{json .State.Paused}},"Restarting":{{json .State.Restarting}},'
    '"OOMKilled":{{json .State.OOMKilled}},"Dead":{{json .State.Dead}},'
    '"Pid":{{json .State.Pid}},"StartedAt":{{json .State.StartedAt}},'
    '"FinishedAt":{{json .State.FinishedAt}},'
    '"Health":{"Status":{{if .State.Health}}{{json .State.Health.Status}}{{else}}null{{end}}}},'
    '"HostConfig":{'
    + ",".join(
        '"' + k + '":{{json .HostConfig.' + k + "}}"
        for k in (
            "NetworkMode",
            "PortBindings",
            "RestartPolicy",
            "NanoCpus",
            "Memory",
            "MemorySwap",
            "ShmSize",
            "PidsLimit",
            "ReadonlyRootfs",
            "Privileged",
        )
    )
    + "},"
    '"NetworkSettings":{"Networks":{{json .NetworkSettings.Networks}},"Ports":{{json .NetworkSettings.Ports}}}}'
)


def selected(c):
    return {
        "Id": c["Id"],
        "Name": c["Name"],
        "Image": c["Image"],
        "Created": c["Created"],
        "State": {
            k: c["State"].get(k)
            for k in (
                "Status",
                "Running",
                "Paused",
                "Restarting",
                "OOMKilled",
                "Dead",
                "Pid",
                "StartedAt",
                "FinishedAt",
            )
        },
        "RestartCount": c["RestartCount"],
        "Health": c["State"].get("Health", {}).get("Status"),
        "Labels": c["Config"].get("Labels", {}),
        "Mounts": [
            {k: m.get(k) for k in ("Type", "Name", "Source", "Destination", "Mode", "RW", "Propagation")}
            for m in c["Mounts"]
        ],
        "HostConfig": {
            k: c["HostConfig"].get(k)
            for k in (
                "NetworkMode",
                "PortBindings",
                "RestartPolicy",
                "NanoCpus",
                "Memory",
                "MemorySwap",
                "ShmSize",
                "PidsLimit",
                "ReadonlyRootfs",
                "Privileged",
            )
        },
        "Networks": {
            k: {f: v.get(f) for f in ("NetworkID", "EndpointID", "IPAddress", "Gateway")}
            for k, v in c["NetworkSettings"]["Networks"].items()
        },
        "Ports": c["NetworkSettings"]["Ports"],
    }


class Docker:
    def __init__(self, check, environment):
        self.check, self.env = check, dict(environment)

    def metadata(self, args):
        fixed = (
            ["info", "--format", "{{json .}}"],
            ["ps", "-aq", "--no-trunc"],
            ["network", "ls", "-q", "--no-trunc"],
            ["volume", "ls", "-q"],
            ["image", "inspect", "--format", "{{json .Id}}", IMAGE],
        )
        inspect_ids = (
            args[:3] == ["inspect", "--format", CONTAINER_FORMAT]
            and len(args) > 3
            and all(re.fullmatch("[0-9a-f]{64}", i) for i in args[3:])
        )
        network_ids = (
            args[:2] == ["network", "inspect"]
            and len(args) > 2
            and all(re.fullmatch("[0-9a-f]{64}", i) for i in args[2:])
        )
        volume_names = (
            args[:2] == ["volume", "inspect"]
            and len(args) > 2
            and all(re.fullmatch("[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", i) for i in args[2:])
        )
        require(args in fixed or inspect_ids or network_ids or volume_names, "Unapproved Docker command")
        self.check()
        result = subprocess.run(
            [DOCKER, "--host", "unix://" + SOCKET, *args], env=self.env, capture_output=True, timeout=8
        )
        require(result.returncode == 0 and len(result.stdout) <= 2097152, "Docker metadata unavailable/oversized")
        self.check()
        return result.stdout.decode()

    def snapshot(self):
        require(stat.S_ISSOCK(Path(SOCKET).lstat().st_mode) and not Path(SOCKET).is_symlink(), "Local socket changed")
        info = json.loads(self.metadata(["info", "--format", "{{json .}}"]))
        require(info["ID"] == DAEMON and info["OperatingSystem"] == "Docker Desktop", "Wrong local daemon")
        ids = self.metadata(["ps", "-aq", "--no-trunc"]).split()
        require(0 < len(ids) <= 32, "Unexpected container cardinality")
        containers = [
            selected(json.loads(c)) for c in self.metadata(["inspect", "--format", CONTAINER_FORMAT, *ids]).splitlines()
        ]
        netids = self.metadata(["network", "ls", "-q", "--no-trunc"]).split()
        require(0 < len(netids) <= 32, "Network cardinality")
        nets = json.loads(self.metadata(["network", "inspect", *netids]))
        names = self.metadata(["volume", "ls", "-q"]).split()
        require(0 < len(names) <= 64, "Volume cardinality")
        vols = json.loads(self.metadata(["volume", "inspect", *names]))
        image = json.loads(self.metadata(["image", "inspect", "--format", "{{json .Id}}", IMAGE]))
        return {
            "daemon": {"ID": info["ID"], "OperatingSystem": info["OperatingSystem"], "socket": SOCKET},
            "containers": sorted(containers, key=lambda c: c["Id"]),
            "networks": sorted(nets, key=lambda n: n["Id"]),
            "volumes": sorted(vols, key=lambda v: v["Name"]),
            "image_id": image,
            "credential": credential_metadata(),
        }

    def mounted_secret(self):
        self.check()
        # Single exact pinned-container read; no shell or secret in argv/env/log.
        result = subprocess.run(
            [
                DOCKER,
                "--host",
                "unix://" + SOCKET,
                "exec",
                "--user",
                "0",
                CONTAINER,
                "/usr/bin/head",
                "-c",
                "65",
                "/run/secrets/f_password",
            ],
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        require(result.returncode == 0 and len(result.stdout) == 64, "Mounted secret unreadable/length mismatch")
        self.check()
        return bytearray(result.stdout)


def verify_resources(actual, baseline):
    require(actual == baseline, "Infrastructure/resource/credential drift")
    require(
        actual["daemon"] == {"ID": DAEMON, "OperatingSystem": "Docker Desktop", "socket": SOCKET}
        and actual["image_id"] == IMAGE,
        "Wrong daemon/image",
    )
    c = next((c for c in actual["containers"] if c["Id"] == CONTAINER), None)
    require(
        c is not None
        and c["Image"] == IMAGE
        and c["State"]["Running"] is True
        and c["Health"] == "healthy"
        and c["RestartCount"] == 0
        and c["Labels"]["com.docker.compose.project"] == "sbom-uuid-w2-f"
        and c["Labels"]["com.docker.compose.service"] == "postgres_f",
        "Wrong/stopped F container",
    )
    require(
        c["Ports"] == {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "56043"}]}
        and set(c["Networks"]) == {NETWORK}
        and c["Networks"][NETWORK]["NetworkID"] == NETWORK_ID,
        "F publication/network",
    )
    h = c["HostConfig"]
    require(
        h["NanoCpus"] == 1000000000
        and h["Memory"] == 536870912
        and h["ShmSize"] == 67108864
        and h["PidsLimit"] == 128
        and h["RestartPolicy"]["Name"] == "no"
        and h["Privileged"] is False,
        "F resource/security limits",
    )
    n = next((n for n in actual["networks"] if n["Id"] == NETWORK_ID), None)
    require(
        n is not None
        and n["Name"] == NETWORK
        and n["Driver"] == "bridge"
        and n["Internal"] is False
        and set(n["Containers"]) == {CONTAINER}
        and n["EnableIPv4"] is True
        and n["EnableIPv6"] is False
        and n["Options"]
        == {
            "com.docker.network.bridge.enable_icc": "false",
            "com.docker.network.bridge.host_binding_ipv4": "127.0.0.1",
            "com.docker.network.enable_ipv4": "true",
            "com.docker.network.enable_ipv6": "false",
        },
        "Network drift",
    )
    mounts = c["Mounts"]
    require(len(mounts) == 2, "Unexpected mount")
    sm = [m for m in mounts if m["Destination"] == "/run/secrets/f_password"]
    dm = [m for m in mounts if m["Destination"] == "/var/lib/postgresql/data"]
    require(
        len(sm) == len(dm) == 1
        and sm[0]["Type"] == "bind"
        and sm[0]["RW"] is False
        and sm[0]["Source"] in {SECRET, "/host_mnt" + SECRET}
        and dm[0]["Type"] == "volume"
        and dm[0]["Name"] == VOLUME
        and dm[0]["RW"] is True,
        "Secret/data mount mismatch",
    )
    users = [c["Id"] for c in actual["containers"] for m in c["Mounts"] if m.get("Name") == VOLUME]
    require(users == [CONTAINER], "Shared F volume")
    require(any(v["Name"] == VOLUME and v["Driver"] == "local" for v in actual["volumes"]), "Missing F volume")
    return c["Networks"][NETWORK]["IPAddress"]


def correlate(expected, docker):
    require(credential_metadata() == expected, "Credential metadata changed")
    fd = os.open(SECRET, os.O_RDONLY | os.O_NOFOLLOW)
    host = mounted = None
    try:
        before = os.fstat(fd)
        require(
            before.st_ino == expected["inode"]
            and before.st_uid == expected["uid"]
            and before.st_nlink == 1
            and stat.S_IMODE(before.st_mode) == 0o600
            and before.st_size == 64,
            "Credential descriptor changed",
        )
        host = bytearray(os.read(fd, 65))
        after = os.fstat(fd)
        require(
            len(host) == 64
            and re.fullmatch(rb"[A-Za-z0-9_-]{64}", host) is not None
            and before.st_mtime_ns == after.st_mtime_ns
            and before.st_ctime_ns == after.st_ctime_ns
            and credential_metadata() == expected,
            "Credential changed while read",
        )
        mounted = docker.mounted_secret()
        require(hmac.compare_digest(host, mounted), "Host/mount content correlation failed")
        require(credential_metadata() == expected, "Credential changed during correlation")
        return host
    except BaseException:
        if isinstance(host, bytearray):
            host[:] = b"\0" * len(host)
        raise
    finally:
        if isinstance(mounted, bytearray):
            mounted[:] = b"\0" * len(mounted)
        os.close(fd)


def verify_dependencies():
    import sys
    from importlib.metadata import distribution

    from security import FOLDER

    lock = unique((FOLDER / "dependency-lock.json").read_bytes())
    cli = Path(DOCKER).resolve()
    python = Path(sys.executable).resolve()
    require(
        str(cli) == lock["docker"]["path"] and sha(cli.read_bytes()) == lock["docker"]["sha256"], "Docker CLI drift"
    )
    require(
        str(python) == lock["python"]["path"]
        and sha(python.read_bytes()) == lock["python"]["sha256"]
        and sys.version == lock["python"]["version"],
        "Python runtime drift",
    )
    for name, expected in lock["distributions"].items():
        dist = distribution(name)
        actual = {
            str(p): sha(Path(dist.locate_file(p)).read_bytes())
            for p in dist.files
            if str(p).endswith((".py", ".so", ".dylib"))
        }
        require(dist.version == expected["version"] and actual == expected["files"], "Installed dependency drift")


def infrastructure_reference(plan):
    ref = plan["infrastructure_reference"]
    require(set(ref) == {"path", "sha256"}, "Infrastructure reference fields")
    return unique(private_bytes(ref["path"], ref["sha256"]))
