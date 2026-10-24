"""Source-derived exact frozen047 model, not a measured PostgreSQL catalog."""

from __future__ import annotations

import re

from w25_inputs import ROOT, digest, require

MARKER = "047_email_verification_tokens"
CREATE_MARKER = "CREATE TABLE public.alembic_version (version_num VARCHAR(128) NOT NULL PRIMARY KEY)"
INSERT_MARKER = "INSERT INTO public.alembic_version (version_num) VALUES (%(revision)s) RETURNING version_num"
MARKER_SQL = "SELECT version_num FROM public.alembic_version"
ADVISORY = "SELECT pg_catalog.pg_try_advisory_xact_lock(7160085085) AS acquired"
RESET = "SET LOCAL search_path = pg_catalog"


def identifier(token):
    if token.startswith('"') and token.endswith('"'):
        token = token[1:-1].replace('""', '"')
    require(re.fullmatch("[a-z_][a-z0-9_]{0,62}", token) is not None, "Unknown identifier")
    return token


def split(tokens):
    parts = []
    start = 0
    depth = 0
    for i, t in enumerate(tokens):
        depth += (t == "(") - (t == ")")
        require(depth >= 0, "Unbalanced source")
        if t == "," and depth == 0:
            parts.append(tokens[start:i])
            start = i + 1
    require(depth == 0, "Unbalanced source")
    parts.append(tokens[start:])
    return parts


def names(tokens):
    require(tokens[0] == "(" and tokens[-1] == ")", "Column list required")
    return [identifier(p[0]) for p in split(tokens[1:-1]) if len(p) == 1]


def normalize(tokens):
    """Explicit representation canonicalization, never edits an executed SQL byte."""
    # Keep literals verbatim; normalize identifier quoting and SQL word case.
    return [t if t.startswith(("'", "E'")) else (identifier(t) if t.startswith('"') else t.lower()) for t in tokens]


def expression(tokens):
    ts = normalize(tokens)
    # Remove only balanced enclosing parentheses; retain interior precedence.
    while ts and ts[0] == "(" and ts[-1] == ")":
        depth = 0
        whole = True
        for x in ts[:-1]:
            depth += (x == "(") - (x == ")")
            if depth == 0:
                whole = False
                break
        if not whole:
            break
        ts = ts[1:-1]

    return ts


def build(api):
    lex = api["fresh"]["pg_lex"]
    frozen = api["fresh"]["frozen_047"]
    source = (ROOT / "scripts/schema/postgresql_047_baseline.sql").read_bytes()
    r = frozen.representation(source)
    require(
        r["execution_sql"].encode()
        == (ROOT / "infra/uuid-migration/fresh-bootstrap/047-execution.proposed.sql").read_bytes(),
        "Frozen execution representation drift",
    )
    entries = lex.statements(r["execution_sql"])
    require(len(entries) == 558 and len(r["directives"]) == 12, "Frozen count")
    tables = {}
    sequences = {}
    constraints = {}
    indexes = {}
    ownership = {}
    defaults = {}

    def constraint(table, name, ts):
        require((table, name) not in constraints, "Duplicate constraint")
        if ts[:2] in {("PRIMARY", "KEY"), ("UNIQUE", "(")}:
            typ = "p" if ts[0] == "PRIMARY" else "u"
            cols = names(ts[2:] if typ == "p" else ts[1:])
            value = {
                "table": table,
                "name": name,
                "type": typ,
                "columns": cols,
                "foreign_table": None,
                "foreign_columns": None,
                "update": "a",
                "delete": "a",
                "match": "s",
                "validated": True,
                "deferrable": False,
                "deferred": False,
                "check": None,
            }
            indexes[(table, name)] = {
                "table": table,
                "name": name,
                "unique": True,
                "primary": typ == "p",
                "columns": cols,
                "predicate": None,
                "method": "btree",
                "opclasses": [None] * len(cols),
            }
        elif ts[:2] == ("FOREIGN", "KEY"):
            ri = ts.index("REFERENCES")
            cols = names(ts[2:ri])
            tail = ts[ri + 1 :]
            require(tail[:2] == ("public", "."), "Foreign schema")
            target = identifier(tail[2])
            end = tail.index(")")
            refcols = names(tail[3 : end + 1])
            action = tail[end + 1 :]
            delete = "a"
            if action:
                require(
                    action in {("ON", "DELETE", "CASCADE"), ("ON", "DELETE", "SET", "NULL")}, "Unreviewed FK action"
                )
                delete = "c" if action[-1] == "CASCADE" else "n"
            value = {
                "table": table,
                "name": name,
                "type": "f",
                "columns": cols,
                "foreign_table": target,
                "foreign_columns": refcols,
                "update": "a",
                "delete": delete,
                "match": "s",
                "validated": True,
                "deferrable": False,
                "deferred": False,
                "check": None,
            }
        elif ts[0] == "CHECK":
            check = expression(ts[1:])
            value = {
                "table": table,
                "name": name,
                "type": "c",
                "columns": [],
                "foreign_table": None,
                "foreign_columns": None,
                "update": "a",
                "delete": "a",
                "match": "s",
                "validated": True,
                "deferrable": False,
                "deferred": False,
                "check": check,
            }
        else:
            raise ValueError("Unreviewed constraint")
        constraints[(table, name)] = value

    for entry in entries:
        t = entry.tokens
        if t[:2] == ("SET", "LOCAL"):
            continue
        if t[:2] == ("CREATE", "TABLE"):
            require(t[2:4] == ("public", ".") and t[5] == "(" and t[-1] == ")", "Table syntax")
            name = identifier(t[4])
            require(name not in tables, "Duplicate table")
            cols = []
            for part in split(t[6:-1]):
                if part[0] == "CONSTRAINT":
                    constraint(name, identifier(part[1]), part[2:])
                    continue
                column = identifier(part[0])
                v = list(part[1:])
                nullable = True
                if v[-2:] == ["NOT", "NULL"]:
                    nullable = False
                    v = v[:-2]
                default = None
                if "DEFAULT" in v:
                    pos = v.index("DEFAULT")
                    default = expression(v[pos + 1 :])
                    v = v[:pos]
                typ = " ".join(v).replace("( ", "(").replace(" )", ")")
                typ = re.sub(r"\s*\(\s*(\d+)\s*\)", r"(\1)", typ).lower()
                require(
                    re.fullmatch(
                        r"integer|bigint|boolean|bytea|text|jsonb?|double precision|character varying(?:\(\d+\))?|timestamp (?:with|without) time zone",
                        typ,
                    )
                    is not None,
                    "Unreviewed column type: " + typ,
                )
                cols.append(
                    {
                        "table": name,
                        "name": column,
                        "position": len(cols) + 1,
                        "type": typ,
                        "not_null": not nullable,
                        "default": default,
                        "identity": "",
                        "generated": "",
                        "acl": None,
                    }
                )
            tables[name] = cols
        elif t[:2] == ("CREATE", "SEQUENCE"):
            require(t[2:4] == ("public", "."), "Sequence schema")
            name = identifier(t[4])
            tail = t[5:]
            integer = tail[:2] == ("AS", "integer")
            tail = tail[2:] if integer else tail
            require(
                tail
                == ("START", "WITH", "1", "INCREMENT", "BY", "1", "NO", "MINVALUE", "NO", "MAXVALUE", "CACHE", "1"),
                "Unreviewed sequence options",
            )
            sequences[name] = {
                "name": name,
                "type": "integer" if integer else "bigint",
                "start": 1,
                "increment": 1,
                "min": 1,
                "max": 2147483647 if integer else 9223372036854775807,
                "cache": 1,
                "cycle": False,
            }
        elif t[:2] == ("ALTER", "SEQUENCE"):
            require(
                t[2:4] == ("public", ".") and t[5:9] == ("OWNED", "BY", "public", ".") and t[10] == ".",
                "Sequence dependency",
            )
            ownership[identifier(t[4])] = {
                "sequence": identifier(t[4]),
                "table": identifier(t[9]),
                "column": identifier(t[11]),
                "dependency": "a",
            }
        elif t[:4] == ("ALTER", "TABLE", "ONLY", "public"):
            require(t[4] == ".", "Table schema")
            name = identifier(t[5])
            tail = t[6:]
            if tail[:2] == ("ADD", "CONSTRAINT"):
                constraint(name, identifier(tail[2]), tail[3:])
            else:
                require(
                    tail[:2] == ("ALTER", "COLUMN") and tail[3:5] == ("SET", "DEFAULT"), "Unreviewed table alteration"
                )
                defaults[(name, identifier(tail[2]))] = expression(tail[5:])
        elif t[:2] in {("CREATE", "INDEX"), ("CREATE", "UNIQUE")}:
            unique = t[1] == "UNIQUE"
            tail = t[3:] if unique else t[2:]
            name = identifier(tail[0])
            require(
                tail[1:4] == ("ON", "public", ".") and tail[5] == "USING" and tail[6] in {"btree", "gin"}, "Index shape"
            )
            table = identifier(tail[4])
            remain = tail[7:]
            where = remain.index("WHERE") if "WHERE" in remain else len(remain)
            parts = split(remain[1 : where - 1])
            require(remain[0] == "(" and remain[where - 1] == ")", "Index columns")
            require(
                all(len(p) == 1 or len(p) == 2 and p[1] == "jsonb_path_ops" and tail[6] == "gin" for p in parts),
                "Expression index not reviewed",
            )
            cols = [identifier(p[0]) for p in parts]
            opclasses = [p[1] if len(p) == 2 else None for p in parts]
            predicate = expression(remain[where + 1 :]) if where < len(remain) else None
            indexes[(table, name)] = {
                "table": table,
                "name": name,
                "unique": unique,
                "primary": False,
                "columns": cols,
                "predicate": predicate,
                "method": tail[6],
                "opclasses": opclasses,
            }

        else:
            raise ValueError("Unrecognized frozen statement")
    for value in constraints.values():
        if value["type"] == "c":
            column_names = {c["name"] for c in tables[value["table"]]}
            value["columns"] = sorted({t for t in value["check"] if t in column_names})
    for (table, col), default in defaults.items():
        row = next(c for c in tables[table] if c["name"] == col)
        require(row["default"] is None, "Duplicate default")
        row["default"] = default
    require(len(tables) == 45 and len(sequences) == 34 and len(ownership) == 34, "Frozen object inventory changed")
    require("alembic_version" not in tables, "Snapshot marker table must be separate")
    model = {
        "tables": tables,
        "sequences": list(sequences.values()),
        "constraints": list(constraints.values()),
        "indexes": list(indexes.values()),
        "sequence_ownership": list(ownership.values()),
    }
    # An explicitly new marker object, never part of the558 source statements.
    model["tables"]["alembic_version"] = [
        {
            "table": "alembic_version",
            "name": "version_num",
            "position": 1,
            "type": "character varying(128)",
            "not_null": True,
            "default": None,
            "identity": "",
            "generated": "",
            "acl": None,
        }
    ]
    model["constraints"].append(
        {
            "table": "alembic_version",
            "name": "alembic_version_pkey",
            "type": "p",
            "columns": ["version_num"],
            "foreign_table": None,
            "foreign_columns": None,
            "update": "a",
            "delete": "a",
            "match": "s",
            "validated": True,
            "deferrable": False,
            "deferred": False,
            "check": None,
        }
    )
    model["indexes"].append(
        {
            "table": "alembic_version",
            "name": "alembic_version_pkey",
            "unique": True,
            "primary": True,
            "columns": ["version_num"],
            "predicate": None,
            "method": "btree",
            "opclasses": [None],
        }
    )
    return {
        "source_sha256": r["source_sha256"],
        "execution_sha256": r["execution_sha256"],
        "transformation_sha256": r["diff_sha256"],
        "statements": [x.sql for x in entries],
        "directives": r["directives"],
        "model": model,
        "model_sha256": digest(model),
        "runtime_accepted": False,
    }
