"""Read authored SQL in deterministic table-then-view bootstrap order."""

from functools import cache
from pathlib import Path

from traust_contracts.paths import storage_dir
from traust_contracts.v1.sql import Dialect
from traust_contracts.v1.sql import bootstrap_files as _bootstrap_files
from traust_contracts.v1.sql import bootstrap_statements as bootstrap_statements

CONTRACT_VERSION = "v1"
#: Storage schema revision, stamped in traust_storage_meta and checked on
#: open. Bump it whenever the DDL changes, so a database created under an
#: older schema is refused instead of failing on its first read or write.
#: 2: artifact_binding.artifact_role and artifact_location (0.48.0). No
#: 1 -> 2 migration ships; a revision-1 database must be recreated.
REVISION = 2


@cache
def query(dialect: Dialect, filename: str) -> str:
    return (storage_dir() / dialect / "queries" / filename).read_text(encoding="utf-8")


#: Views that other views select FROM, in the order they must be created.
#: Alphabetical order is not dependency order -- `current_finding` sorts
#: before `report_current` but selects from it, and PostgreSQL resolves a
#: view's references at CREATE time, so the glob order alone fails there
#: while silently succeeding on SQLite.
#: THE SCHEMA IS THE REFERENCE FOR WHAT A VIEW MUST CARRY. A view is not
#: correct because its numbers match another projection -- two projections
#: dropping the same fields agree perfectly and are both wrong. Check it
#: against the artifact's JSON Schema, and let
#: tests/test_view_contract_coverage.py fail you if a declared field never
#: reaches SQL. See storage/v1/README.md, "The schema is the reference".
VIEW_ORDER: tuple[str, ...] = (
    "binding_current.sql",
    "report_current.sql",
    "ownership_current.sql",
    "current_finding.sql",
    "threat_current.sql",
    "validation_current.sql",
    "finding_first_seen.sql",
    "finding_timeline.sql",
    "pqc_posture.sql",
    "sla_clock.sql",
    "sla_threshold.sql",
    # Reads current_finding, so it must follow it.
    "pattern_exposure.sql",
    # Reads threat_current and current_binding.
    "attack_coverage.sql",
)


def bootstrap_files(dialect: Dialect) -> list[Path]:
    """Return dependency-ordered tables followed by dependency-ordered views."""
    return _bootstrap_files(
        storage_dir(),
        dialect,
        first_tables=("artifact_evidence", "artifact_binding", "artifact_location"),
        view_order=VIEW_ORDER,
    )
