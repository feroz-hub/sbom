# W2.5 focused setting-source correction — offline review v2

No live authority. Original source lock, pending template and W2.5 private
packages/candidates remain historical bytes. The new contract selects only
`source-lock.w25.v2.json`; that lock additionally pins the original lock itself.
Its candidates need independent source review and fresh explicit action approval.
No authorization or expiry is extended. No SQL, transaction, model or budget
artifact changes are made.

## Confirmed defect and four phases

The original validator expected client sources after executing SET LOCAL and
therefore rejected the independently constructed correct post-body fixture:
`ValueError: Accepted F security/session drift: settings`.
Original test fixtures repeated the faulty expectation; they now distinguish a
write session with local assignments from an independent new readback session.
The focused tests specify their own exact values/sources without generating
fixtures through the production expectation helper.

The existing boolean call contract selects four explicit observation phases:

| readonly | after | Phase | Six monitored local settings' source | transaction_read_only |
|---|---|---|---|---|
| true | false | initial_readonly | client | on / session |
| false | false | locked_pre_ddl | client | off / session |
| false | true | post_body | session | off / session |
| true | true | independent_readback | client | on / session |

These booleans must be actual bool values. Full list equality still checks all
16 monitored settings, including exact values, source metadata, missing/extra/
duplicate rows and ordering. The expected-source change is restricted to the
six-row intersection below. No arbitrary source, wildcard or ignored field.

| Monitored setting | All four phase values | Initial / locked / readback source | Post-body source |
|---|---|---|---|
| statement_timeout | 30000 | client | session |
| lock_timeout | 1000 | client | session |
| idle_in_transaction_session_timeout | 30000 | client | session |
| check_function_bodies | on | client | session |
| row_security | on | client | session |
| search_path | pg_catalog | client | session |

Timeout values remain the existing W2.5 startup 30s/1s/30s, not the earlier F
acceptance session's 2s/250ms/5s. search_path is pg_catalog, public during body
construction, then pg_catalog after the unchanged SET LOCAL reset; post-body
observations occur only after that reset. check_function_bodies and row_security
stay on even though setting their existing value changes source metadata.
The remaining nine settings besides transaction_read_only retain exactly their
accepted F rows: default_transaction_read_only, listen_addresses,
max_connections, password_encryption, port, shared_buffers, ssl,
stats_fetch_consistency, work_mem. The transaction setting remains session-sourced
and requires the exact effective RO/RW state in settings and identity observations.

## PostgreSQL REL_16_15 source basis

[ExecSetVariableStmt in guc_funcs.c](https://github.com/postgres/postgres/blob/REL_16_15/src/backend/utils/misc/guc_funcs.c)
uses GUC_ACTION_LOCAL with PGC_S_SESSION for local value assignments. Its settings
view projection reports the current source. [guc_tables.c](https://github.com/postgres/postgres/blob/REL_16_15/src/backend/utils/misc/guc_tables.c)
maps PGC_S_SESSION to session and declares the three timeouts as integer,
row_security/check_function_bodies as Boolean, and search_path as string.
All six are USERSET; the booleans/timeouts have no overriding check/assign hooks,
while search_path has its normal validation/assignment hooks.

[set_config_option_ext and AtEOXact_GUC in guc.c](https://github.com/postgres/postgres/blob/REL_16_15/src/backend/utils/misc/guc.c)
install source metadata in each successful Boolean/integer/string assignment,
even when the value equals its prior value. Source priority and validation still
apply. Local state and source are stacked; top-level commit/abort restores prior
local values and source metadata. No persistent session SET is introduced here.
A new readback connection independently reapplies startup options; it does not
inherit the completed write connection's local state.

The accepted initial client sources are actual historical F evidence. Source
support for startup option attribution is [process_postgres_switches](https://github.com/postgres/postgres/blob/REL_16_15/src/backend/tcop/postgres.c).
The source ordering and LOCAL action definitions are in
[guc.h](https://github.com/postgres/postgres/blob/REL_16_15/src/include/utils/guc.h).
This is static source reasoning, not PostgreSQL runtime verification.

## Every reviewed directive considered

All 12 proposed statements remain byte-for-byte unchanged. Successful assignment
uses the corresponding generic type branch; normal hooks/validation must still
succeed. Only six have source fields in the existing fixed settings query.

| SET LOCAL name | Type | Reviewed value | Source field monitored |
|---|---|---|---|
| statement_timeout | integer, milliseconds | 30s | yes |
| lock_timeout | integer, milliseconds | 1s | yes |
| idle_in_transaction_session_timeout | integer, milliseconds | 30s | yes |
| client_encoding | string, encoding hooks | UTF8 | no |
| standard_conforming_strings | Boolean | on | no |
| search_path | string, namespace hooks | pg_catalog, public; later pg_catalog | yes |
| check_function_bodies | Boolean | on | yes |
| xmloption | enum | content | no |
| client_min_messages | enum | warning | no |
| row_security | Boolean | on | yes |
| default_tablespace | string, tablespace hook | empty | no |
| default_table_access_method | string, table-AM hook | heap | no |

The six unmonitored source fields are not fabricated as runtime observations or
added to the query. Source types/hooks and enum assignment were reviewed, but
this patch neither expands the SQL scope nor claims fresh runtime evidence.
All 558 statements, marker operations, source-derived schema, query budgets,
W2.4C transaction kernel, rollback/unknown-COMMIT/closure rules and separately
authorized readback boundaries remain unchanged. Any unexpected live metadata
still requires STOP rather than assumption or relaxation.
