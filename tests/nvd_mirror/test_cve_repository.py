"""Phase 2.6 — SqlAlchemyCveRepository tests on SQLite.

Production runs on PostgreSQL; SQLite is the dev/test path. The
repository routes through SQLAlchemy's dialect-specific ``insert`` so
ON CONFLICT semantics are exercised on both dialects.
"""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.nvd_mirror.adapters.cve_repository import (
    SqlAlchemyCveRepository,
    _criterion_covers_version,
    _parse_cpe23,
)
from app.nvd_mirror.domain.models import CpeCriterion, CveRecord


UTC = timezone.utc


@pytest.fixture()
def session() -> Session:
    """Per-test in-memory SQLite session with mirror tables created."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    Path(path).unlink(missing_ok=True)
    url = f"sqlite:///{path}"

    # Build engine + create the mirror tables in isolation. We do NOT
    # call create_all on the full app Base here because that would force
    # the legacy app.models tables to be created and pollute the test.
    from app.db import Base
    import app.nvd_mirror.db.models  # noqa: F401 — register tables

    engine = create_engine(url)
    Base.metadata.create_all(bind=engine)

    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    s = SessionLocal()
    try:
        yield s
    finally:
        s.close()
        engine.dispose()
        Path(path).unlink(missing_ok=True)


def _make_record(
    *,
    cve_id: str = "CVE-2024-0001",
    last_modified: datetime | None = None,
    vuln_status: str = "Analyzed",
    cpe_criteria: tuple[CpeCriterion, ...] = (),
    score_v31: float | None = 9.8,
) -> CveRecord:
    return CveRecord(
        cve_id=cve_id,
        last_modified=last_modified or datetime(2024, 6, 1, tzinfo=UTC),
        published=datetime(2024, 1, 1, tzinfo=UTC),
        vuln_status=vuln_status,
        description_en="example",
        score_v40=None,
        score_v31=score_v31,
        score_v2=None,
        severity_text="CRITICAL",
        vector_string=None,
        aliases=("GHSA-xxxx-yyyy-zzzz",),
        cpe_criteria=cpe_criteria,
        references=(f"https://nvd.nist.gov/vuln/detail/{cve_id}",),
        raw={"id": cve_id},
    )


def _crit(
    vendor: str = "apache",
    product: str = "log4j",
    version: str = "*",
    *,
    start_inc: str | None = None,
    end_exc: str | None = None,
) -> CpeCriterion:
    return CpeCriterion(
        criteria=f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*",
        criteria_stem=f"{vendor}:{product}",
        vulnerable=True,
        version_start_including=start_inc,
        version_start_excluding=None,
        version_end_including=None,
        version_end_excluding=end_exc,
    )


# --- upsert_batch ---------------------------------------------------------


def test_upsert_inserts_new_rows(session: Session) -> None:
    repo = SqlAlchemyCveRepository(session)
    n = repo.upsert_batch([_make_record(cve_id="CVE-2024-1"), _make_record(cve_id="CVE-2024-2")])
    session.commit()
    assert n == 2
    assert repo.find_by_cve_id("CVE-2024-1") is not None
    assert repo.find_by_cve_id("CVE-2024-2") is not None


def test_upsert_replay_is_noop(session: Session) -> None:
    repo = SqlAlchemyCveRepository(session)
    rec = _make_record(cve_id="CVE-2024-1", score_v31=7.5)
    repo.upsert_batch([rec])
    session.commit()
    repo.upsert_batch([rec])
    session.commit()
    found = repo.find_by_cve_id("CVE-2024-1")
    assert found is not None
    assert found.score_v31 == 7.5


def test_upsert_newer_last_modified_wins(session: Session) -> None:
    repo = SqlAlchemyCveRepository(session)
    older = _make_record(
        cve_id="CVE-2024-1",
        last_modified=datetime(2024, 1, 1, tzinfo=UTC),
        score_v31=5.0,
    )
    newer = _make_record(
        cve_id="CVE-2024-1",
        last_modified=datetime(2024, 6, 1, tzinfo=UTC),
        score_v31=9.8,
    )
    repo.upsert_batch([older])
    session.commit()
    repo.upsert_batch([newer])
    session.commit()
    found = repo.find_by_cve_id("CVE-2024-1")
    assert found is not None
    assert found.score_v31 == 9.8


def test_upsert_older_last_modified_does_not_overwrite(session: Session) -> None:
    repo = SqlAlchemyCveRepository(session)
    newer = _make_record(
        cve_id="CVE-2024-1",
        last_modified=datetime(2024, 6, 1, tzinfo=UTC),
        score_v31=9.8,
    )
    older = _make_record(
        cve_id="CVE-2024-1",
        last_modified=datetime(2024, 1, 1, tzinfo=UTC),
        score_v31=1.0,
    )
    repo.upsert_batch([newer])
    session.commit()
    repo.upsert_batch([older])
    session.commit()
    found = repo.find_by_cve_id("CVE-2024-1")
    assert found is not None
    assert found.score_v31 == 9.8  # NOT overwritten


def test_upsert_empty_returns_zero(session: Session) -> None:
    assert SqlAlchemyCveRepository(session).upsert_batch([]) == 0


def test_upsert_chunks_large_batch(session: Session) -> None:
    """Batch larger than UPSERT_CHUNK_SIZE still inserts every record."""
    from app.nvd_mirror.adapters.cve_repository import UPSERT_CHUNK_SIZE

    n_records = UPSERT_CHUNK_SIZE + 5
    records = [_make_record(cve_id=f"CVE-2024-{i:05d}") for i in range(n_records)]
    repo = SqlAlchemyCveRepository(session)
    repo.upsert_batch(records)
    session.commit()
    assert repo.find_by_cve_id("CVE-2024-00000") is not None
    assert repo.find_by_cve_id(f"CVE-2024-{n_records - 1:05d}") is not None


# --- find_by_cve_id -------------------------------------------------------


def test_find_by_cve_id_missing(session: Session) -> None:
    assert SqlAlchemyCveRepository(session).find_by_cve_id("CVE-9999-0") is None


def test_round_trip_preserves_aliases_and_criteria(session: Session) -> None:
    crit = _crit("apache", "log4j", "2.14.0")
    repo = SqlAlchemyCveRepository(session)
    repo.upsert_batch([_make_record(cve_id="CVE-2021-44228", cpe_criteria=(crit,))])
    session.commit()
    found = repo.find_by_cve_id("CVE-2021-44228")
    assert found is not None
    assert found.aliases == ("GHSA-xxxx-yyyy-zzzz",)
    assert len(found.cpe_criteria) == 1
    assert found.cpe_criteria[0].criteria_stem == "apache:log4j"
    assert found.last_modified.tzinfo is not None  # UTC restored


# --- soft_mark_rejected ---------------------------------------------------


def test_soft_mark_rejected_updates_status(session: Session) -> None:
    repo = SqlAlchemyCveRepository(session)
    repo.upsert_batch([_make_record(cve_id="CVE-2024-1"), _make_record(cve_id="CVE-2024-2")])
    session.commit()
    n = repo.soft_mark_rejected(["CVE-2024-1"])
    session.commit()
    assert n == 1
    found = repo.find_by_cve_id("CVE-2024-1")
    assert found is not None
    assert found.vuln_status == "Rejected"
    assert repo.find_by_cve_id("CVE-2024-2").vuln_status == "Analyzed"


def test_soft_mark_rejected_empty_list(session: Session) -> None:
    assert SqlAlchemyCveRepository(session).soft_mark_rejected([]) == 0


# --- find_by_cpe ---------------------------------------------------------


def test_find_by_cpe_exact_version_match(session: Session) -> None:
    repo = SqlAlchemyCveRepository(session)
    repo.upsert_batch(
        [_make_record(cve_id="CVE-2021-44228", cpe_criteria=(_crit(version="2.14.0"),))]
    )
    session.commit()
    hits = repo.find_by_cpe("cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*")
    assert [h.cve_id for h in hits] == ["CVE-2021-44228"]


def test_find_by_cpe_excludes_rejected(session: Session) -> None:
    repo = SqlAlchemyCveRepository(session)
    repo.upsert_batch(
        [_make_record(cve_id="CVE-2021-44228", vuln_status="Rejected", cpe_criteria=(_crit(version="2.14.0"),))]
    )
    session.commit()
    assert repo.find_by_cpe("cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*") == []


def test_find_by_cpe_version_range_inside(session: Session) -> None:
    repo = SqlAlchemyCveRepository(session)
    crit = _crit(version="*", start_inc="2.0.0", end_exc="2.17.0")
    repo.upsert_batch(
        [_make_record(cve_id="CVE-2021-44228", cpe_criteria=(crit,))]
    )
    session.commit()
    hits = repo.find_by_cpe("cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*")
    assert [h.cve_id for h in hits] == ["CVE-2021-44228"]


def test_find_by_cpe_version_range_excludes_outside(session: Session) -> None:
    repo = SqlAlchemyCveRepository(session)
    crit = _crit(version="*", start_inc="2.0.0", end_exc="2.17.0")
    repo.upsert_batch(
        [_make_record(cve_id="CVE-2021-44228", cpe_criteria=(crit,))]
    )
    session.commit()
    # 2.17.0 is excluded by end_exc
    assert repo.find_by_cpe("cpe:2.3:a:apache:log4j:2.17.0:*:*:*:*:*:*:*") == []
    # 1.x is below start_inc
    assert repo.find_by_cpe("cpe:2.3:a:apache:log4j:1.2.17:*:*:*:*:*:*:*") == []


def test_find_by_cpe_unknown_product(session: Session) -> None:
    assert (
        SqlAlchemyCveRepository(session).find_by_cpe(
            "cpe:2.3:a:nobody:nothing:1.0.0:*:*:*:*:*:*:*"
        )
        == []
    )


def test_find_by_cpe_malformed_input(session: Session) -> None:
    assert SqlAlchemyCveRepository(session).find_by_cpe("not-a-cpe-string") == []
    assert SqlAlchemyCveRepository(session).find_by_cpe("") == []


# --- helpers --------------------------------------------------------------


def test_parse_cpe23_happy_path() -> None:
    p = _parse_cpe23("cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*")
    assert p == ("apache", "log4j", "2.14.0")


def test_parse_cpe23_rejects_short_input() -> None:
    assert _parse_cpe23("cpe:2.3:a:apache") is None
    assert _parse_cpe23("") is None


def test_criterion_covers_unbounded_wildcard_target() -> None:
    d = {"criteria": "cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*"}
    assert _criterion_covers_version(d, "*") is True


def test_criterion_covers_with_unparseable_version() -> None:
    """Defensive bypass when version strings fail to parse."""
    d = {"version_start_including": "2.0.0", "version_end_excluding": "2.17.0"}
    # Even with junk version, defensive bypass returns True (when bounds exist)
    assert _criterion_covers_version(d, "garbage-version") is True
