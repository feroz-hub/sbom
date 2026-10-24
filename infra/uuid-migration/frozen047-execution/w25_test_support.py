"""Synthetic driver/catalog helpers only. No real connector or credential read."""

from __future__ import annotations

import copy
from types import SimpleNamespace as NS
from unittest.mock import Mock

import w25_catalog as c
from w25_contract import baseline
from w25_inputs import FOLDER, reviewed, unique
from w25_runtime import Transport, create_meter, factories
from w25_schema import ADVISORY, CREATE_MARKER, INSERT_MARKER, MARKER, MARKER_SQL, RESET, build

_CACHE = None


def inputs():
    global _CACHE
    if _CACHE is None:
        api = reviewed()
        _CACHE = (api, build(api), baseline(api))
    return _CACHE


def post_rows(base, model, *, readonly, marker):
    data = copy.deepcopy(base)
    data["identity"][0]["transaction_read_only"] = "on" if readonly else "off"
    for r in data["settings"]:
        if r["name"] in {"statement_timeout", "idle_in_transaction_session_timeout"}:
            r["setting"] = "30000"
        if r["name"] == "lock_timeout":
            r["setting"] = "1000"
        if r["name"] == "transaction_read_only":
            r["setting"] = "on" if readonly else "off"
        # Independent synthetic PG16 fixture: only the write post-body session
        # executed SET LOCAL. A new RO readback connection did not.
        if not readonly and r["name"] in {
            "statement_timeout",
            "lock_timeout",
            "idle_in_transaction_session_timeout",
            "check_function_bodies",
            "row_security",
            "search_path",
        }:
            r["source"] = "session"
    data["relations"] = [
        {"nspname": "public", "relname": name, "relkind": kind, "relpersistence": "p"}
        for kind, names in [
            ("r", model["tables"]),
            ("S", [r["name"] for r in model["sequences"]]),
            ("i", [r["name"] for r in model["indexes"]]),
        ]
        for name in names
    ]
    data["types"] = [
        {"nspname": "public", "typname": name, "typtype": kind}
        for table in model["tables"]
        for name, kind in [(table, "c"), ("_" + table, "b")]
    ]
    data["columns"] = []
    for rows in model["tables"].values():
        for row in rows:
            row = copy.deepcopy(row)
            row["default"] = " ".join(row["default"]) if row["default"] is not None else None
            row["collation"] = "default" if row["type"].startswith(("text", "character varying")) else None
            data["columns"].append(row)
    data["alembic"] = [{"relation": "public.alembic_version"}]
    data["constraints"] = copy.deepcopy(model["constraints"])
    for row in data["constraints"]:
        row["check"] = " ".join(row["check"]) if row["check"] is not None else None
    data["indexes"] = copy.deepcopy(model["indexes"])
    for row in data["indexes"]:
        row.update(
            predicate=" ".join(row["predicate"]) if row["predicate"] is not None else None,
            valid=True,
            ready=True,
            live=True,
            no_expressions=True,
            no_include=True,
            options=[0] * len(row["columns"]),
            nulls_not_distinct=False,
        )
    data["sequences"] = copy.deepcopy(model["sequences"])
    data["sequence_ownership"] = copy.deepcopy(model["sequence_ownership"])
    data["business"] = [{"table": name, "has_rows": False} for name in model["tables"] if name != "alembic_version"]
    data["marker"] = marker
    data["storage"] = []
    for i, row in enumerate(data["relations"], 20000):
        kind = row["relkind"]
        name = row["relname"]
        method = (
            "heap"
            if kind == "r"
            else next(x["method"] for x in model["indexes"] if x["name"] == name)
            if kind == "i"
            else ""
        )
        data["storage"].append(
            {
                "oid": i,
                "schema": "public",
                "name": name,
                "kind": kind,
                "owner": "uuid_w2_f_bootstrap",
                "acl": None,
                "persistence": "p",
                "rls": False,
                "force_rls": False,
                "default_options": True,
                "default_tablespace": True,
                "replica_identity": "d" if kind == "r" else "n",
                "toast_oid": 0,
                "parent_oid": None,
                "parent": None,
                "toast_parent_oid": None,
                "toast_parent": None,
                "inherits": False,
                "populated": True,
                "partition": False,
                "method": method,
            }
        )
    return data


class Raw:
    def __init__(self, base, representation, *, committed=False):
        self.base = base
        self.r = representation
        self.autocommit = False
        self.isolation_level = 2
        self.read_only = True
        self.prepare_threshold = None
        self.closed = False
        self.info = NS(transaction_status="IDLE")
        self.pgconn = NS(used_password=True)
        self.calls = []
        self.body = 558 if committed else 0
        self.marker_created = committed
        self.marker = [{"version_num": MARKER}] if committed else []
        self.committed = committed
        self.fail_sql = None
        self.fail_commit = False
        self.fail_rollback = False
        self.fail_close = False
        self.post_mutation = None
        self.add_notice_handler = Mock()

    def cursor(self):
        return Cursor(self)

    def commit(self):
        self.calls.append(("COMMIT", None))
        self.committed = True
        if self.fail_commit:
            raise RuntimeError("synthetic uncertain COMMIT")
        self.info.transaction_status = "IDLE"

    def rollback(self):
        self.calls.append(("ROLLBACK", None))
        if self.fail_rollback:
            raise RuntimeError("synthetic rollback failure")
        if not self.committed:
            self.body = 0
            self.marker = []
            self.marker_created = False
        self.info.transaction_status = "IDLE"

    def close(self):
        if self.fail_close:
            raise RuntimeError("synthetic close failure")
        self.closed = True


class Cursor:
    def __init__(self, raw):
        self.raw = raw
        self.description = None
        self.rowcount = -1
        self.rows = []

    def execute(self, sql, params=None):
        r = self.raw
        if r.info.transaction_status == "IDLE":
            r.calls.append(("IMPLICIT_BEGIN_RO" if r.read_only else "IMPLICIT_BEGIN_RW", None))
            r.info.transaction_status = "INTRANS"
        r.calls.append((sql, params))
        if r.fail_sql == sql:
            r.info.transaction_status = "INERROR"
            raise RuntimeError("synthetic SQL failure")
        init = {
            "select pg_catalog.version()": "PostgreSQL 16.15 on SYNTHETIC",
            "select current_schema()": "pg_catalog",
            "show transaction isolation level": "read committed",
            "show standard_conforming_strings": "on",
        }
        if sql in init:
            data = [{"synthetic": init[sql]}]
        elif sql.startswith("SELECT typname AS name"):
            data = []
        elif sql == ADVISORY:
            data = [{"acquired": True}]
        elif sql in r.r["statements"]:
            require_index = r.r["statements"].index(sql)
            assert require_index == r.body
            r.body += 1
            data = []
        elif sql == CREATE_MARKER:
            assert r.body == 558
            r.marker_created = True
            data = []
        elif sql == RESET:
            data = []
        elif sql == INSERT_MARKER:
            assert r.body == 558 and r.marker_created and r.marker == [] and params == {"revision": MARKER}
            r.marker = [{"version_num": MARKER}]
            self.rowcount = 1
            data = r.marker
        elif sql == MARKER_SQL:
            data = r.marker
        else:
            api, _, _ = inputs()
            mapping = {v: k for k, v in api["readonly"]["catalog"].QUERIES.items()}
            mapping[c.COLUMNS] = "columns"
            mapping.update({v: k for k, v in c.EXTRA.items()})
            if sql.startswith("SELECT EXISTS (SELECT 1 FROM public."):
                data = [{"has_rows": False}]
            elif sql in mapping:
                key = mapping[sql]
                if r.marker_created:
                    d = post_rows(r.base, r.r["model"], readonly=r.read_only, marker=r.marker)
                    if r.post_mutation:
                        r.post_mutation(d)
                else:
                    d = copy.deepcopy(r.base)
                    d["identity"][0]["transaction_read_only"] = "on" if r.read_only else "off"
                    for x in d["settings"]:
                        if x["name"] in {"statement_timeout", "idle_in_transaction_session_timeout"}:
                            x["setting"] = "30000"
                        elif x["name"] == "lock_timeout":
                            x["setting"] = "1000"
                        elif x["name"] == "transaction_read_only":
                            x["setting"] = "on" if r.read_only else "off"
                data = d[key]
            else:
                raise AssertionError("Unrecognized synthetic SQL: " + sql)
        self.description = (
            [(k, None, None, None, None, None, None) for k in data[0]]
            if data
            else [("synthetic", None, None, None, None, None, None)]
        )
        self.rows = [tuple(row.values()) for row in data]

    def fetchone(self):
        return self.rows.pop(0) if self.rows else None

    def fetchmany(self, n):
        rows = self.rows[:n]
        self.rows = self.rows[n:]
        return rows

    def fetchall(self):
        rows = self.rows
        self.rows = []
        return rows

    def close(self):
        pass


def fixture(action="unit_execute", *, committed=False, journal=None):
    api, r, base = inputs()
    plan = unique((FOLDER / "observation-budget.w25.json").read_bytes())
    allow = unique((FOLDER / "sql-allowlist.w25.json").read_bytes())["driver_sha256"][action]
    journal = Mock() if journal is None else journal
    meter = create_meter(api, plan, action, allow, journal)
    raw = Raw(base, r, committed=committed)
    authority = NS(
        action=action,
        api=api,
        baseline=base,
        expected="a" * 64,
        recheck=Mock(),
        check_window=Mock(),
        plan={"model_sha256": r["model_sha256"], "sources_lock_sha256": "b" * 64},
    )
    connector = Mock(return_value=raw)
    secret = bytearray(b"SYNTHETIC_ONLY_PASSWORD")
    transport = Transport(
        authority,
        meter,
        journal,
        connector=connector,
        factories=factories(api),
        resource_gate=Mock(),
        correlate=Mock(return_value=secret),
    )
    return NS(
        api=api,
        r=r,
        base=base,
        journal=journal,
        meter=meter,
        raw=raw,
        authority=authority,
        connector=connector,
        secret=secret,
        transport=transport,
    )
