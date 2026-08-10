"""SBOM validation pipeline — eight-stage layered validator.

See :doc:`../../docs/adr/0007-sbom-validation-architecture` for the design
and :doc:`../../docs/validation-error-codes` for the error-code reference.
"""

from .errors import ErrorReport, Severity, ValidationError
from .pipeline import run

__all__ = ["ErrorReport", "Severity", "ValidationError", "run"]
