"""Pure normalization of independently collected F Docker metadata.

No Docker CLI/API is called. A future reviewed runner must obtain each raw
object from the exact local socket, never substitute manifest-derived metadata.
"""

from __future__ import annotations

from security import F_SECRET, require


def normalize(plan, *, daemon, container, volume, network, volume_users, credential, digest):
    r = plan["resources"]
    require(
        daemon["ID"] == r["daemon_id"]
        and daemon["OperatingSystem"] == "Docker Desktop"
        and daemon["socket"] == r["socket"],
        "Unexpected daemon/socket/platform",
    )
    require(
        container["Id"] == r["container_id"]
        and container["Image"] == r["image_id"]
        and container["State"]["StartedAt"] == r["started_at"]
        and container["State"]["Running"] is True,
        "Container replacement/restart/image drift",
    )
    labels = container["Config"]["Labels"]
    host = container["HostConfig"]
    mounts = container["Mounts"]
    secret = [m for m in mounts if m["Destination"] == "/run/secrets/f_password"]
    data = [m for m in mounts if m["Destination"] == "/var/lib/postgresql/data"]
    require(
        len(secret) == len(data) == 1
        and data[0]["Type"] == "volume"
        and data[0]["Name"] == "sbom-uuid-w2-f_f_pgdata"
        and data[0]["RW"] is True
        and len(mounts) == 2,
        "Unexpected mounts/storage",
    )
    require(
        volume["Name"] == "sbom-uuid-w2-f_f_pgdata"
        and volume["Driver"] == "local"
        and volume["Labels"]["com.docker.compose.project"] == "sbom-uuid-w2-f"
        and network["Name"] == "sbom-uuid-w2-f_f_access"
        and network["Id"] == r["network_id"]
        and network["Driver"] == "bridge"
        and network["Labels"]["com.docker.compose.project"] == "sbom-uuid-w2-f"
        and set(network["Containers"]) == {r["container_id"]},
        "Foreign volume/network attachment",
    )
    networks = container["NetworkSettings"]["Networks"]
    ports = container["NetworkSettings"]["Ports"]
    require(
        set(ports) == {"5432/tcp"} and ports["5432/tcp"] == [{"HostIp": "127.0.0.1", "HostPort": "56043"}],
        "Wrong/non-loopback publication",
    )
    # Volume identity is approved from freshly observed creation/driver/options/
    # mountpoint/labels, not a guessed cluster ID or reused volume name alone.
    identity = digest({k: volume[k] for k in ("Name", "Driver", "CreatedAt", "Mountpoint", "Labels", "Options")})
    return {
        "pins": {
            "daemon_id": daemon["ID"],
            "socket": daemon["socket"],
            "container_id": container["Id"],
            "image_id": container["Image"],
            "started_at": container["State"]["StartedAt"],
            "network_id": network["Id"],
            "volume_identity": identity,
        },
        "labels": {"project": labels["com.docker.compose.project"], "service": labels["com.docker.compose.service"]},
        "networks": [{"name": n, "id": v["NetworkID"]} for n, v in sorted(networks.items())],
        "volume": {"name": data[0]["Name"], "identity": identity, "destination": data[0]["Destination"]},
        "exclusive_volume_users": sorted(set(volume_users)),
        "publication": [{"host_ip": "127.0.0.1", "host_port": 56043, "container_port": 5432}],
        "mount": {
            "type": secret[0]["Type"],
            "source": secret[0]["Source"],
            "destination": secret[0]["Destination"],
            "rw": secret[0]["RW"],
        },
        "credential": credential,
        "desktop": True,
        "platform": daemon["OperatingSystem"],
        "secret_mount_count": len(secret),
        "settings": {
            "running": container["State"]["Running"],
            "restart_count": container["RestartCount"],
            "nano_cpus": host["NanoCpus"],
            "memory": host["Memory"],
            "shm_size": host["ShmSize"],
            "pids_limit": host["PidsLimit"],
            "restart_policy": host["RestartPolicy"]["Name"],
            "network_internal": network["Internal"],
            "icc": network["Options"]["com.docker.network.bridge.enable_icc"],
        },
    }


def host_read(path, metadata, *, stat_reader, opener):
    """Injected OS O_NOFOLLOW descriptor reader with before/after provenance.

    opener contract: (path, maxbytes) -> (before_metadata, bytearray, after_metadata).
    No real opener is provided by W2.4A. Secret bytes never enter evidence.
    """
    require(path == F_SECRET and stat_reader(path) == metadata, "Secret metadata changed")
    before, content, after = opener(path, 4096)
    try:
        require(
            before == after == metadata
            and isinstance(content, bytearray)
            and len(content) == metadata["size"]
            and 20 <= len(content) <= 4096
            and stat_reader(path) == metadata,
            "Secret descriptor/provenance changed",
        )
        return content
    except BaseException:
        if isinstance(content, bytearray):
            content[:] = b"\0" * len(content)
        raise


class SecretFiles:
    """Descriptor-safe host reader with injected OS interface, not CLI-wired.

    Only F_SECRET is eligible. os_api must be an explicitly reviewed OS adapter;
    mounted_reader is separately reviewed/bounded and must not log its result.
    No real OS or Docker reader is constructed in offline tests.
    """

    def __init__(self, os_api, mounted_reader):
        self.os = os_api
        self.mounted_reader = mounted_reader

    def stat_host(self, path):
        from security import file_metadata

        return file_metadata(path, lstat=self.os.lstat)

    def read_host(self, path, expected):
        import os
        import stat

        require(path == F_SECRET and self.stat_host(path) == expected, "Credential metadata mismatch")
        fd = self.os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        content = bytearray()

        def verify():
            s = self.os.fstat(fd)
            require(
                stat.S_ISREG(s.st_mode)
                and s.st_nlink == 1
                and s.st_uid == expected["uid"]
                and stat.S_IMODE(s.st_mode) == 0o600
                and s.st_ino == expected["inode"]
                and s.st_size == expected["size"]
                and s.st_mtime_ns == expected["mtime_ns"]
                and s.st_ctime_ns == expected["ctime_ns"],
                "Secret descriptor changed",
            )

        try:
            verify()
            while len(content) <= 4096:
                chunk = self.os.read(fd, 4097 - len(content))
                if not chunk:
                    break
                content.extend(chunk)
            verify()
            require(
                len(content) == expected["size"] and 20 <= len(content) <= 4096 and self.stat_host(path) == expected,
                "Secret changed or oversized",
            )
            return content
        except BaseException:
            content[:] = b"\0" * len(content)
            raise
        finally:
            self.os.close(fd)

    def read_mounted(self, container_id, destination, limit):
        require(destination == "/run/secrets/f_password" and limit == 4096, "Wrong mounted secret request")
        result = self.mounted_reader(container_id, destination, limit)
        require(isinstance(result, bytearray) and len(result) <= limit, "Unbounded secret reader")
        return result
