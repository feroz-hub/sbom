"""Complete metadata registration for the explicit fresh-installation command.

Importing this module is inert. No application runtime or legacy migration replay.
"""

from importlib import import_module


def application_metadata():
    for module in ("app.models", "app.models_reports", "app.nvd_mirror.db.models"):
        import_module(module)
    return import_module("app.db").Base.metadata
