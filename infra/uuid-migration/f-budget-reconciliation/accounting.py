"""Pure AST/source accounting. Never imports or invokes a migration function.

Expected relation prefixes describe the intended successful PostgreSQL fresh
path, not evidence it ran. Conditional CREATE guards are retained as observations
requiring runtime acceptance, not predictions about arbitrary databases.
"""

from __future__ import annotations

import ast
import math

from review_inputs import digest, require, reviewed, sha

EXCLUDED = {
    "alembic_version",
    "authorization_roles",
    "authorization_permissions",
    "authorization_role_permissions",
    "authorization_audit_log",
}
ACTIONS = ("unit_validate", "unit_execute", "unit_readback")


def reachable(tree):
    funcs = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    require("upgrade" in funcs, "Missing upgrade declaration")
    todo, seen = ["upgrade"], set()
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        for n in ast.walk(funcs[name]):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in funcs:
                todo.append(n.func.id)
    require("downgrade" not in seen, "Unexpected upgrade-to-downgrade call")
    return {name: funcs[name] for name in sorted(seen)}


def source_inventory(raw):
    tree = ast.parse(raw)
    constants = {}
    for n in tree.body:
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
            try:
                constants[n.targets[0].id] = ast.literal_eval(n.value)
            except (ValueError, TypeError):
                pass
    funcs = reachable(tree)
    effects, reads, reflection, loops = [], [], [], []
    for name, func in funcs.items():
        for n in ast.walk(func):
            if isinstance(n, (ast.For, ast.While)):
                loops.append({"function": name, "line": n.lineno, "header": ast.unparse(n).splitlines()[0]})
            if not isinstance(n, ast.Call):
                continue
            call = ast.unparse(n.func)
            if (
                isinstance(n.func, ast.Attribute)
                and n.func.value.__class__ is ast.Name
                and n.func.value.id == "op"
                and n.func.attr in {"create_table", "drop_table", "rename_table"}
            ):
                value = n.args[0]
                table = constants.get(value.id) if isinstance(value, ast.Name) else ast.literal_eval(value)
                require(isinstance(table, str), "Unresolved table effect")
                require(n.func.attr == "create_table", "Unreviewed destructive table effect on fresh path")
                require(
                    all(k.arg != "schema" or ast.literal_eval(k.value) == "public" for k in n.keywords),
                    "Nonpublic table effect",
                )
                effects.append({"operation": "create_if_absent", "table": table, "function": name, "line": n.lineno})
            if call.endswith(
                (
                    "inspect",
                    "Table",
                    "reflect",
                    "get_table_names",
                    "get_columns",
                    "get_indexes",
                    "get_foreign_keys",
                    "get_check_constraints",
                    "get_unique_constraints",
                    "get_pk_constraint",
                )
            ):
                reflection.append({"function": name, "line": n.lineno, "call": call})
            # Read-capable execute sites include Core selects and parameterized
            # sa.text calls. This is a site inventory, never a runtime call count.
            if call.endswith((".execute", ".scalar", ".scalar_one", ".scalar_one_or_none")) or call == "_rows":
                reads.append({"function": name, "line": n.lineno, "call": call, "expression": ast.unparse(n)})
            # Raw CREATE/DROP/RENAME TABLE requires separate analysis. None is
            # present on the reviewed historical successful path.
            if call.endswith(".execute"):
                for value in ast.walk(n):
                    if isinstance(value, ast.Constant) and isinstance(value.value, str):
                        upper = " ".join(value.value.upper().split())
                        require(
                            not any(v in upper for v in ("CREATE TABLE ", "DROP TABLE ", "RENAME TABLE ")),
                            "Raw table SQL requires separate model",
                        )
    return {
        "table_effects": sorted(effects, key=lambda r: r["line"]),
        "read_capable_sites": sorted(reads, key=lambda r: r["line"]),
        "reflection_sites": sorted(reflection, key=lambda r: r["line"]),
        "loop_sites": sorted(loops, key=lambda r: r["line"]),
        "reachable_functions": sorted(funcs),
        "source_sha256": sha(raw),
    }


def pass_counts(names, *, fresh=False, final=False):
    """Exact W2.4A collect() driver-query count on a matching successful prefix."""
    require(len(set(names)) == len(names), "Duplicate relation prefix")
    names = set(names)
    return {
        "full_catalog": 27,
        "identity": 1,
        "clients": 1,
        "locks": 1,
        "business_emptiness": len(names - EXCLUDED),
        "version_marker": int("alembic_version" in names),
        "reference_data": 4 if "authorization_roles" in names else 0,
        "fresh_catalog_duplicate": 24 if fresh else 0,
        "finalization_snapshot": 17 if final else 0,
    }


def finalize_body(position, total_tables):
    """Successful pinned086–091 body; server-internal DO subqueries excluded.

    Two _prefix traversals: guard1 +6*(column/CHECK/triggers/rules/index=5)
    +2 name-collision SELECTs per not-yet-finalized table. Both _empty_business
    calls query relations and all except three reference tables+version table.
    """
    return {
        "identity_and_settings_and_advisory_and_initial_marker_clients_events": 6,
        "prefix_before": 43 - 2 * position,
        "prefix_after": 41 - 2 * position,
        "uuid_data_preconditions": 12,
        "empty_business_twice": 2 * (1 + total_tables - 4),
        "snapshots_twice": 34,
        "target_column": 1,
        "last_predecessor_marker": 1,
    }


def build(root):
    prior, modules, registry, _ = reviewed(root)
    refs = modules["source_registry"].reference_api(root, registry)
    require(
        len(refs["fresh_catalog"].QUERIES) == 24
        and len(modules["observations"].catalog_queries(root, registry)) == 27
        and len(modules["observations"].REFERENCE_SQL) == 4,
        "Collector shape changed",
    )
    frozen = refs["frozen_047"].representation((root / "scripts/schema/postgresql_047_baseline.sql").read_bytes())
    frozen_names = sorted(row["tokens"][4] for row in frozen["inventory"] if row["family"] == "table")
    require(len(frozen_names) == 45, "Frozen table inventory changed")
    state, rows = set(), []
    for unit in registry["units"]:
        number = int(unit["next"][:3])
        before = sorted(state)
        raw = (root / unit["source"]).read_bytes()
        if number == 47:
            additions = frozen_names
            inventory = {
                "table_effects": [],
                "read_capable_sites": [],
                "reflection_sites": [],
                "loop_sites": [],
                "source_sha256": sha(raw),
                "reachable_functions": [],
            }
        else:
            inventory = source_inventory(raw)
            additions = [e["table"] for e in inventory["table_effects"]]
            require(not set(additions) & state, "Unexpected existing table CREATE")
        state.update(additions)
        if number == 47:
            state.add("alembic_version")
        after = sorted(state)
        fresh = number == 47
        final = number >= 86
        pre = pass_counts(before, fresh=fresh, final=final)
        post = pass_counts(after)
        pre_total = sum(pre.values())
        post_total = sum(post.values())
        # Execute includes advisorySELECT and the post-marker SELECT. Marker
        # RETURNING is DML and is charged only to its marker quota.
        body_detail = finalize_body(number - 86, len(state)) if final else {}
        body_exact = sum(body_detail.values()) if final else 0 if fresh or number >= 80 else None
        if body_exact is None:
            # Explicit policy reservations, NOT proven runtime upper bounds.
            # A site can repeat per row/cache miss. Every resulting driver call
            # must still satisfy the exact SQL allowlist and this hard cap.
            read_cap = 16 * len(inventory["read_capable_sites"])
            reflect_cap = 24 * len(inventory["reflection_sites"])
            loop_cap = 8 * len(inventory["loop_sites"])
            body_cap = max(8, read_cap + reflect_cap + loop_cap)
            body_basis = {
                "read_site_reserve": read_cap,
                "reflection_site_reserve": reflect_cap,
                "loop_reserve": loop_cap,
                "hidden_driver_read_floor": max(0, 8 - read_cap - reflect_cap - loop_cap),
            }
        else:
            body_cap = body_exact
            body_basis = {"exact_pinned_body_queries": body_exact}
        body_nonquery = (
            558
            if fresh
            else (9 if number == 80 else 8)
            if 80 <= number <= 85
            else (2 * len(state) + 5)
            if final
            else None
        )
        nonquery = {
            "coordinator_table_locks": 0 if fresh else len(before) + 1,
            "body_migration_driver_statements_exact": body_nonquery,
            "body_migration_runtime_dependent": 48 <= number <= 79,
            "marker_statements": 2 if fresh else 1,
            "session_statements": 1 if fresh else 2 if number < 80 else 0,
            "write_transaction_controls": 4,
            "readonly_transaction_controls": 2,
        }
        components = {
            "preflight": pre,
            "locked_reinspection": dict(pre),
            "post_body": post,
            "readback": dict(post),
            "coordinator_selects": 2,
            "body": body_detail,
        }
        deterministic = 2 * pre_total + post_total + 2 + (body_exact or 0)
        actions = {}
        for action in ACTIONS:
            phases = {"initialization": 16}
            if action == "unit_execute":
                phases.update(
                    preflight=pre_total,
                    locked_reinspection=pre_total,
                    post_body=post_total,
                    coordinator=2,
                    body=body_cap,
                )
            elif action == "unit_validate":
                phases["preflight"] = pre_total
            else:
                phases["readback"] = post_total
            minimum = (
                deterministic if action == "unit_execute" else pre_total if action == "unit_validate" else post_total
            )
            # Reserve per-phase runtime uncertainty above, then add at most7
            # rounding slots. No phase can consume another phase's spare quota.
            allocated = sum(phases.values())
            rounded = 8 * math.ceil(allocated / 8)
            limit = max(unit["budgets"]["catalog_queries"], rounded) if action == "unit_execute" else rounded
            actions[action] = {
                "deterministic_queries": minimum,
                "phase_caps": phases,
                "phase_cap_sum": allocated,
                "rounding_margin": rounded - allocated,
                "unallocated_legacy_headroom": limit - rounded,
                "limits": {**unit["budgets"], "catalog_queries": limit},
                "body_reservation_basis": body_basis if action == "unit_execute" else {},
                "body_driver_count_static_exact": body_exact is not None and action == "unit_execute",
                "runtime_upper_bound_proven": False,
            }
        rows.append(
            {
                "unit": unit["next"],
                "previous": unit["previous"],
                "kind": unit["kind"],
                "source": unit["source"],
                "source_sha256": unit["source_sha256"],
                "prefix_before": before,
                "prefix_after": after,
                "tables_before": len(before),
                "tables_after": len(after),
                "business_before": len(set(before) - EXCLUDED),
                "business_after": len(state - EXCLUDED),
                "added_tables": additions,
                "components": components,
                "body_exact_queries": body_exact,
                "body_inventory": inventory,
                "nonquery_accounting": nonquery,
                "old_limits": unit["budgets"],
                "actions": actions,
                "old_query_limit_below_deterministic_minimum": deterministic > unit["budgets"]["catalog_queries"],
            }
        )
    require(len(rows) == 45 and len(state) == 72, "Successful fresh-path relation model changed")
    return {
        "schema": "w24b-observation-plan-v2",
        "accepted": False,
        "approvals": {},
        "strategy": "B",
        "prior_source_pin_sha256": digest(prior["sources"]),
        "catalog_format": "unchangedW23-full27+W21-fresh24+W22-final17",
        "prefix_status": "STATIC INTENDED SUCCESS PATH; NOT RUNTIME ACCEPTED",
        "sql_optimization": "NONE; all existing coverage retained",
        "initialization_reservation": 16,
        "historical_site_policy": "max(8,16/read-capable site +24/reflection site +8/loop site); reservations NOT runtime proofs",
        "rows": rows,
    }
