"""Additional per-phase query ceilings around the unchanged W2.4A driver meter.

No connector or execution activation. The exact driver allowlist, owned controls,
non-query quotas, cooperative deadline and cleanup rules stay in the old meter.
"""

from __future__ import annotations

from contextlib import contextmanager

from budget_policy import check_prefix, select
from review_inputs import require


def create_meter(base_class, plan, revision, action, allowlist, parser, **kwargs):
    """Dependency injected, tested with the exact pinned driver-meter class.

    Phase counter increments only after the original meter accepts the call;
    logical observation wrappers never increment it. A failed durable-evidence
    write can leave a conservative global reservation, never an unmetered call.
    """
    selection = select(plan, revision, action)

    class ScopedMeter(base_class):
        def __init__(self):
            super().__init__(dict(selection["limits"]), allowlist, parser, **kwargs)
            self.phase_caps = dict(selection["phase_caps"])
            self.phase_counts = dict.fromkeys(self.phase_caps, 0)
            self.active_phase = None

        def assert_authority(self, authority):
            require(
                authority.args[1] == revision
                and authority.args[2] == action
                and authority.plan["schema"] == "w24b-f-unit-v2"
                and authority.plan["budgets"] == self.limits,
                "Budget/action/unit authority mismatch",
            )

        def prefix(self, names):
            check_prefix(plan, revision, self.active_phase, names)

        @contextmanager
        def phase(self, name):
            require(name in self.phase_caps and self.active_phase is None, "Unknown/nested observation phase")
            previous_category = self.category
            self.active_phase = name
            try:
                yield
            finally:
                self.active_phase = None
                self.category = previous_category

        def driver(self, statement, parameters, many):
            require(isinstance(statement, str), "Unreviewed SQL representation")
            framed = self.parser(statement if statement.rstrip().endswith(";") else statement + ";")
            is_query = len(framed) == 1 and framed[0].tokens[0].upper() in {"SELECT", "SHOW"}
            count = 1
            if is_query:
                require(self.active_phase in self.phase_caps, "Unattributed driver query")
                if many:
                    require(isinstance(parameters, (list, tuple)) and len(parameters) > 0, "Unbounded executemany")
                    count = len(parameters)
                require(
                    self.phase_counts[self.active_phase] + count <= self.phase_caps[self.active_phase],
                    "Observation phase query budget exhausted",
                )
            result = super().driver(statement, parameters, many)
            if is_query:
                self.phase_counts[self.active_phase] += count
            return result

    return ScopedMeter()
