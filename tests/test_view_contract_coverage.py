"""A view must expose what its contract declares, or say why not.

The failure this catches is silent and was made three times in one
sitting: a view is authored from the fields someone happened to need,
the numbers agree with whatever else projects the same artifact, and
nobody notices that two thirds of the contract never reached SQL.

Agreement between two projections proves nothing when both drop the
same fields. `advisory_exposure` matched the legacy SQLite projection
exactly on every classification bucket while both were dropping 26 of
the 40 fields `impact-analysis.schema.json` declares -- including every
piece of evidence explaining HOW a classification was reached, which is
the entire point of an impact analysis.

So the reference is the SCHEMA. For every fan-out view, the fields the
contract declares on the item being fanned out must appear in the view,
or be listed in EXEMPT with a reason a reviewer can disagree with.
"""

from __future__ import annotations

import json
import re

import pytest

from traust_contracts.paths import schema_dir, storage_dir

#: A field satisfied by FLATTENED columns rather than one of its own name.
#: `source` is already split into source_type/source_ref/actor_kind, and
#: risk_weight follows it -- so the check looks for the parts, not the name.
#: Listed explicitly: a prefix rule would silently accept a partial split.
FLATTENED: dict[tuple[str, str], tuple[str, ...]] = {
    ("layer_event", "source"): ("source_type", "source_ref", "actor_kind", "source_reported_by"),
    ("layer_event", "disposition"): ("validity", "resolution", "severity", "embargo"),
    ("layer_event", "risk_weight"): (
        "risk_lambda",
        "risk_weights_version",
        "risk_tenancy_profile",
        "risk_profile_source",
    ),
    ("report_finding", "id"): ("finding_id",),
    ("report_finding", "disposition"): (
        "validity",
        "resolution",
        "assurance",
        "last_updated",
        "conflict",
        "fp_overridden",
        "fp_reassertion_blocked",
        "refuted_awaiting_signoff",
        "severity_override",
    ),
    ("cloud_config_finding", "id"): ("finding_id",),
    # _declared flattens an evidence block into its members, so the mapping
    # is per MEMBER: the block is prefixed, not kept whole.
    ("verification_finding", "evidence"): (
        "evidence_explanation",
        "evidence_framework_reference",
        "evidence_original_code",
        "evidence_patched_code",
    ),
    ("verification_finding", "explanation"): ("evidence_explanation",),
    ("verification_finding", "framework_reference"): ("evidence_framework_reference",),
    ("verification_finding", "original_code"): ("evidence_original_code",),
    ("verification_finding", "patched_code"): ("evidence_patched_code",),
    ("verification_regression", "id"): ("regression_id",),
    ("threat", "actor"): ("actors",),
    ("threat", "id"): ("threat_id",),
    ("cloud_config_finding", "disposition"): (
        "validity",
        "resolution",
        "assurance",
        "last_updated",
        "conflict",
        "fp_overridden",
        "fp_reassertion_blocked",
        "refuted_awaiting_signoff",
        "severity_override",
    ),
}

#: projection table -> (schema file, JSON pointer to the ITEM it fans out).
#: A view can only expose what its table carries, so the table is where the
#: contract is actually kept or lost -- gating only the views let
#: report_finding sit at 6 of 27 declared fields unnoticed.
FAN_OUT_TABLES: dict[str, tuple[str, tuple[str, ...]]] = {
    "report_finding": ("report.schema.json", ("findings",)),
    "cloud_config_finding": ("cloud-config-findings-current.schema.json", ("findings",)),
    "layer_event": ("layer.schema.json", ("events",)),
    "validation_finding": ("validation.schema.json", ("validated_findings",)),
    "threat": ("threat-model.schema.json", ("threats",)),
    "compliance_result": ("compliance-assessment.schema.json", ("results",)),
    "verification_finding": ("verification.schema.json", ("verified_findings",)),
    "verification_regression": ("verification.schema.json", ("regressions",)),
    "remediation_source": ("remediation.schema.json", ("source_findings",)),
    "attack_chain": ("validation.schema.json", ("attack_chains",)),
}

#: view -> (schema file, JSON pointer to the ITEM the view fans out).
#: A pointer of () means the document root.
FAN_OUT_VIEWS: dict[str, tuple[str, tuple[str, ...]]] = {
    "advisory_exposure": ("impact-analysis.schema.json", ("repos",)),
    "validation_current": ("validation.schema.json", ("validated_findings",)),
    "threat_current": ("threat-model.schema.json", ("threats",)),
}

#: Fields a view deliberately does not carry, each with the reason.
#: A reason a reviewer can disagree with -- not "not needed yet".
EXEMPT: dict[tuple[str, str], str] = {
    ("advisory_exposure", "evidence"): ("the block itself; its members are checked individually"),
    ("validation_current", "steps"): (
        "the per-step execution log, one level below this view's grain. "
        "Its scope_reason is already surfaced as skip_reason on the "
        "projection; the rest belongs to a steps view if one is ever needed"
    ),
    ("validation_current", "source_report"): (
        "the path of the report validated, which is resolver bookkeeping "
        "rather than an outcome; the binding carries the identity"
    ),
    ("validation_finding", "steps"): (
        "the per-step execution log, one level below this table's grain -- "
        "one row per step, not per finding. Its scope_reason is already "
        "surfaced as skip_reason; the rest belongs to a steps table if a "
        "query ever justifies one"
    ),
    ("validation_finding", "source_report"): (
        "the path of the report validated, which is resolver bookkeeping "
        "rather than an outcome; the binding carries the identity"
    ),
    ("validation_finding", "evidence"): (
        "flattened already -- its members reach the table individually as "
        "evidence_grade and grade_rationale, so the block itself would be "
        "a second copy"
    ),
    ("threat_current", "actor"): "exposed as `actors`, plural, on the projection",
    ("threat_current", "id"): "exposed as `threat_id`; `id` collides across models",
}


def _deref(schema: dict, node: dict) -> dict:
    return schema["$defs"][node["$ref"].split("/")[-1]] if "$ref" in node else node


def _item_properties(schema: dict, pointer: tuple[str, ...]) -> dict:
    node = schema
    for step in pointer:
        node = _deref(schema, node["properties"][step])
        if node.get("type") == "array":
            node = _deref(schema, node["items"])
    return node.get("properties", {})


def _declared(schema: dict, pointer: tuple[str, ...]) -> set[str]:
    """Every field the contract declares on the item, evidence flattened.

    A nested evidence/detail block is where the interesting fields hide,
    so it is flattened rather than treated as one opaque column -- that
    is exactly how 15 of impact-analysis's 19 evidence fields went
    missing without anyone noticing.
    """
    props = _item_properties(schema, pointer)
    names = set(props)
    for nested in ("evidence",):
        block = props.get(nested)
        if isinstance(block, dict):
            names |= set(_deref(schema, block).get("properties", {}))
    return names


@pytest.mark.parametrize("view", sorted(FAN_OUT_VIEWS))
def test_view_exposes_what_its_contract_declares(view: str) -> None:
    schema_file, pointer = FAN_OUT_VIEWS[view]
    schema = json.loads((schema_dir() / schema_file).read_text(encoding="utf-8"))
    sql = (storage_dir() / "sqlite" / "views" / f"{view}.sql").read_text(encoding="utf-8")

    declared = _declared(schema, pointer)
    missing = {name for name in declared if not re.search(rf"\b{re.escape(name)}\b", sql)}
    unexplained = sorted(name for name in missing if (view, name) not in EXEMPT)
    assert not unexplained, (
        f"{view} drops {len(unexplained)} field(s) {schema_file} declares: "
        f"{', '.join(unexplained)}. Expose them, or add an EXEMPT entry "
        f"with a reason. A field the contract declares and no view carries "
        f"is unreachable from SQL no matter what is loaded."
    )


def _without_comments(sql: str) -> str:
    """SQL minus its `--` comments.

    The prose in these files names the very fields it explains, so a plain
    grep over the whole text reports a column as present when only its
    rationale is. That is not hypothetical: `layer_event` read as carrying
    `finding` and `disposition` because both words appear in comments,
    while neither was a column.
    """
    return re.sub(r"--[^\n]*", "", sql)


@pytest.mark.parametrize("table", sorted(FAN_OUT_TABLES))
def test_table_carries_what_its_contract_declares(table: str) -> None:
    schema_file, pointer = FAN_OUT_TABLES[table]
    schema = json.loads((schema_dir() / schema_file).read_text(encoding="utf-8"))
    ddl = _without_comments(
        (storage_dir() / "sqlite" / "schema" / f"{table}.sql").read_text(encoding="utf-8")
    )

    missing = []
    for name in sorted(_declared(schema, pointer)):
        parts = FLATTENED.get((table, name))
        if parts is not None:
            if all(re.search(rf"\b{re.escape(p)}\b", ddl) for p in parts):
                continue
        elif re.search(rf"\b{re.escape(name)}\b", ddl):
            continue
        if (table, name) not in EXEMPT:
            missing.append(name)
    assert not missing, (
        f"{table} drops {len(missing)} field(s) {schema_file} declares: "
        f"{', '.join(missing)}. Add the column, flatten it and list the parts "
        f"in FLATTENED, or add an EXEMPT entry with a reason. A view can only "
        f"expose what its table carries."
    )


def test_both_dialects_declare_the_same_columns() -> None:
    """A column added to one dialect and not the other is a silent NULL."""
    drift = []
    for table in FAN_OUT_TABLES:
        cols = {}
        for dialect in ("sqlite", "postgres"):
            ddl = _without_comments(
                (storage_dir() / dialect / "schema" / f"{table}.sql").read_text(encoding="utf-8")
            )
            body = ddl[ddl.index("(") : ddl.index("PRIMARY KEY")]
            cols[dialect] = {
                m.group(1) for m in re.finditer(r"^\s{4}([a-z_][a-z0-9_]*)\s+\S", body, re.M)
            }
        if cols["sqlite"] != cols["postgres"]:
            drift.append(
                f"{table}: sqlite-only {sorted(cols['sqlite'] - cols['postgres'])}, "
                f"postgres-only {sorted(cols['postgres'] - cols['sqlite'])}"
            )
    assert not drift, f"dialect column drift: {drift}"


def test_every_exemption_is_still_needed() -> None:
    """An exemption for a field a view now carries hides the next gap."""
    stale = []
    for (relation, name), _reason in EXEMPT.items():
        spec = FAN_OUT_VIEWS.get(relation) or FAN_OUT_TABLES.get(relation)
        assert spec, f"EXEMPT names {relation}, which is neither a gated view nor table"
        schema_file, pointer = spec
        schema = json.loads((schema_dir() / schema_file).read_text(encoding="utf-8"))
        if name not in _declared(schema, pointer):
            stale.append(f"{relation}:{name} (no longer declared by {schema_file})")
    assert not stale, f"stale exemptions: {stale}"


def test_both_dialects_expose_the_same_fields() -> None:
    """Parity at the field level, not just the view-name level.

    A field added to one dialect and forgotten in the other is a view
    that answers differently depending on the adopter's database.
    """
    for view in FAN_OUT_VIEWS:
        names = {}
        for dialect in ("sqlite", "postgres"):
            sql = (storage_dir() / dialect / "views" / f"{view}.sql").read_text(encoding="utf-8")
            # select-list aliases only: `AS name,` or `AS name` at a line
            # end. `AS entry(value)` is a LATERAL table alias, not a column.
            names[dialect] = set(re.findall(r"\bAS ([a-z_][a-z0-9_]*)\s*(?:,|$)", sql, re.M))
        assert names["sqlite"] == names["postgres"], (
            f"{view}: dialects expose different columns — "
            f"sqlite-only {sorted(names['sqlite'] - names['postgres'])}, "
            f"postgres-only {sorted(names['postgres'] - names['sqlite'])}"
        )


#: Views that exist to be composed by other views, not read directly.
#: An intermediate with no reader is correct; a CONSUMPTION view with no
#: reader is authored, gated and unreachable -- which is what
#: validation_current was until revision 14.
INTERMEDIATE_VIEWS = {
    "binding_current": "the latest-binding filter every other view joins",
    "current_finding": "the spine open/hardening/distinct/census all read",
    "report_current": "one report per subject, composed into current_finding",
    "ownership_current": "the owner join, composed into every scoped view",
    "finding_first_seen": "the open-clock, composed into finding_timeline",
    "sla_clock": "the policy clock, composed into finding_sla",
}


def test_every_consumption_view_has_a_query_and_a_reader() -> None:
    """A view nothing can call is not a consumption surface.

    Catches the gap in both directions: a view added without its
    `.list.sql`, and a `.list.sql` added without the `Store.query_*`
    method that makes it reachable from Python.
    """
    from traust_contracts.v1.storage import Store

    views = {p.stem for p in (storage_dir() / "sqlite" / "views").glob("*.sql")}
    unknown = INTERMEDIATE_VIEWS.keys() - views
    assert not unknown, f"INTERMEDIATE_VIEWS names views that do not exist: {sorted(unknown)}"

    problems = []
    for view in sorted(views - INTERMEDIATE_VIEWS.keys()):
        for dialect in ("sqlite", "postgres"):
            if not (storage_dir() / dialect / "queries" / f"{view}.list.sql").is_file():
                problems.append(f"{view}: no {dialect} .list.sql")
        if not hasattr(Store, f"query_{view}"):
            problems.append(f"{view}: no Store.query_{view}")
    assert not problems, (
        "consumption views that cannot be read: "
        + "; ".join(problems)
        + ". Add the query and the reader, or declare it in INTERMEDIATE_VIEWS."
    )
