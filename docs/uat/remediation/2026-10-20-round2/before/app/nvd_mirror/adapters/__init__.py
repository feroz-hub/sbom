"""Concrete adapters implementing the bounded-context ports.

Imports are intentionally lazy at this package level — pulling the
SQLAlchemy adapters into the import graph just because someone wants the
Fernet adapter would defeat the layering. Callers should import directly
from the module they need (e.g. ``from app.nvd_mirror.adapters.secrets
import FernetSecretsAdapter``).
"""
