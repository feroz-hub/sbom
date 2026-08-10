"""Port interfaces (typing.Protocol). One file per concern."""

from .clock import ClockPort
from .remote import NvdRemotePort
from .repositories import (
    CveRepositoryPort,
    SettingsRepositoryPort,
    SyncRunRepositoryPort,
)
from .secrets import SecretsPort

__all__ = [
    "ClockPort",
    "CveRepositoryPort",
    "NvdRemotePort",
    "SecretsPort",
    "SettingsRepositoryPort",
    "SyncRunRepositoryPort",
]
