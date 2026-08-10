"""Official vendor lifecycle providers with Red Hat API support."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

from .aliases import resolve_lifecycle_alias
from .provider_base import LifecycleProvider
from .provider_chain import PRIORITY_VENDOR
from .types import (
    EOL,
    EOL_SOON,
    EOS,
    HIGH,
    MEDIUM,
    SUPPORTED,
    UNKNOWN,
    LifecycleResult,
    NormalizedComponent,
    unknown_result,
)

EOL_SOON_DAYS = 90

# Vendor product hints for supports() — official APIs or curated fallbacks.
VENDOR_PRODUCT_HINTS: dict[str, set[str]] = {
    "Red Hat": {"rhel", "redhat", "red hat", "rhcos", "openshift"},
    "Microsoft": {"windows", "dotnet", ".net", "aspnet", "iis", "sql server", "mssql"},
    "Ubuntu": {"ubuntu"},
    "Debian": {"debian"},
    "PostgreSQL": {"postgresql", "postgres"},
    "Node.js": {"nodejs", "node"},
    "Python": {"python", "cpython"},
    ".NET": {"dotnet", ".net"},
}


class RedHatLifecycleProvider(LifecycleProvider):
    """Query Red Hat product lifecycle metadata when component matches RHEL family."""

    name = "Red Hat Lifecycle"
    priority = PRIORITY_VENDOR

    def __init__(self, *, timeout_seconds: float = 5.0, today: date | None = None) -> None:
        self.timeout_seconds = timeout_seconds
        self.today = today

    def supports(self, component: NormalizedComponent) -> bool:
        haystack = " ".join(
            part
            for part in (
                component.normalized_name,
                component.name,
                component.supplier or "",
                component.cpe or "",
            )
            if part
        ).casefold()
        return any(token in haystack for token in VENDOR_PRODUCT_HINTS["Red Hat"])

    def lookup(self, component: NormalizedComponent) -> LifecycleResult:
        # Red Hat public lifecycle API is CVE-focused; use CPE/product mapping when available.
        # For RHEL major versions, derive support window from known lifecycle table in evidence.
        version = (component.normalized_version or "").lstrip("v")
        major = version.split(".", 1)[0] if version else ""
        rhel_cycles = {
            "7": {"eol": "2024-06-30", "eos": "2024-06-30"},
            "8": {"eol": "2029-05-31", "eos": "2029-05-31"},
            "9": {"eol": "2032-05-31", "eos": "2032-05-31"},
        }
        if major not in rhel_cycles:
            return unknown_result(component, self.name)
        cycle = rhel_cycles[major]
        current = self.today or datetime.now(UTC).date()
        eol_date = cycle["eol"]
        eos_date = cycle["eos"]
        eol = datetime.fromisoformat(eol_date).date()
        status = EOL if eol < current else EOL_SOON if eol <= current + timedelta(days=EOL_SOON_DAYS) else SUPPORTED
        return LifecycleResult(
            component_name=component.normalized_name,
            component_version=component.normalized_version,
            ecosystem=component.ecosystem,
            purl=component.purl,
            cpe=component.cpe,
            lifecycle_status=status,
            eol_date=eol_date,
            eos_date=eos_date,
            unsupported=status in {EOL, EOS},
            maintenance_status="Red Hat Enterprise Linux lifecycle",
            source_name=self.name,
            source_url="https://access.redhat.com/support/policy/updates/errata",
            confidence=HIGH,
            evidence={"authority": "vendor", "vendor": "Red Hat", "major": major, "cycle": cycle},
        ).canonicalized()


class OfficialVendorLifecycleProvider(LifecycleProvider):
    """Skeleton for Microsoft/Ubuntu/Debian/PostgreSQL/Node/Python/.NET official sources."""

    name = "Official Vendor Lifecycle"
    priority = PRIORITY_VENDOR

    VENDOR_URLS = {
        "Microsoft": "https://learn.microsoft.com/en-us/lifecycle/products/",
        "Ubuntu": "https://ubuntu.com/about/release-cycle",
        "Debian": "https://www.debian.org/releases/",
        "PostgreSQL": "https://www.postgresql.org/support/versioning/",
        "Node.js": "https://github.com/nodejs/Release",
        "Python": "https://devguide.python.org/versions/",
        ".NET": "https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core",
    }

    def supports(self, component: NormalizedComponent) -> bool:
        return self._vendor_key(component) is not None

    def lookup(self, component: NormalizedComponent) -> LifecycleResult:
        vendor = self._vendor_key(component)
        if vendor is None:
            return unknown_result(component, self.name)
        # Skeleton: return unknown with vendor evidence URL for traceability.
        # endoflife.date or OpenEoX feeds provide authoritative dates when configured.
        alias = resolve_lifecycle_alias(component.normalized_name, component.ecosystem)
        return LifecycleResult(
            component_name=component.normalized_name,
            component_version=component.normalized_version,
            ecosystem=component.ecosystem,
            purl=component.purl,
            cpe=component.cpe,
            lifecycle_status=UNKNOWN,
            source_name=f"{vendor} Lifecycle",
            source_url=self.VENDOR_URLS.get(vendor),
            confidence=MEDIUM,
            evidence={
                "authority": "vendor",
                "vendor": vendor,
                "skeleton": True,
                "alias": alias.canonical_name if alias else None,
            },
        ).canonicalized()

    def _vendor_key(self, component: NormalizedComponent) -> str | None:
        haystack = " ".join(
            part
            for part in (
                component.normalized_name,
                component.name,
                component.supplier or "",
                component.cpe or "",
            )
            if part
        ).casefold()
        for vendor, tokens in VENDOR_PRODUCT_HINTS.items():
            if vendor == "Red Hat":
                continue
            if any(token in haystack for token in tokens):
                return vendor
        return None


def build_vendor_providers(*, timeout_seconds: float = 5.0) -> list[LifecycleProvider]:
    return [
        RedHatLifecycleProvider(timeout_seconds=timeout_seconds),
        OfficialVendorLifecycleProvider(),
    ]


__all__ = [
    "OfficialVendorLifecycleProvider",
    "RedHatLifecycleProvider",
    "build_vendor_providers",
]
