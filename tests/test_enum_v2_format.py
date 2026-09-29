"""Gate for the v2 enum format (enums/format/v2.schema.json + ci/enum_v2.py).

Three things are tested:

- the format itself: the meta-schema is valid, and each rule ci/enum_v2.py
  enforces rejects a file that breaks it;
- expressiveness: tests/fixtures/enums_v2 is an illustrative v2 set that writes
  every conversion the classifier assessment proposes (its section 7 mapping
  table). The fixture values are NOT decided vocabulary;
- enforcement: every real file in enums/v2 passes the same checks, so v2
  vocabularies are checked from the first one that lands.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("enum_v2", ROOT / "ci" / "enum_v2.py")
enum_v2 = importlib.util.module_from_spec(_spec)
sys.modules["enum_v2"] = enum_v2
_spec.loader.exec_module(enum_v2)

FIXTURES = ROOT / "tests" / "fixtures" / "enums_v2"
V1 = enum_v2.v1_values()

# Every v1 value the assessment's mapping table converts. Each must have an
# alias in the fixture set.
ASSESSMENT_ROWS = (
    [
        ("validity", v)
        for v in ("not_verified", "confirmed", "false_positive", "hardening", "corrected")
    ]
    + [("event_validity", v) for v in ("confirmed", "false_positive", "hardening", "corrected")]
    + [
        ("verdict", v)
        for v in ("true_positive", "hardening", "false_positive", "undetermined", "duplicate")
    ]
    + [
        ("triage_verify_verdict", v)
        for v in (
            "exploitable",
            "mitigated",
            "needs_manual_test",
            "confirmed",
            "refuted",
            "hardening",
        )
    ]
    + [
        ("validation_verdict", v)
        for v in ("confirmed", "refuted", "inconclusive", "blocked_by_scope", "not_attempted")
    ]
    + [("remediation_validation_verdict", "not_validated")]
    + [
        ("impact_classification", v)
        for v in (
            "affected",
            "likely_affected",
            "not_observed",
            "inconclusive",
            "version_not_in_range",
            "not_imported",
        )
    ]
    + [
        ("disposition_resolution", v)
        for v in (
            "open",
            "resolved",
            "partially_resolved",
            "risk_accepted",
            "fix_in_progress",
            "regression_introduced",
        )
    ]
    + [
        ("verification_verdict", v)
        for v in (
            "resolved",
            "partially_resolved",
            "risk_accepted",
            "unresolved",
            "regression",
            "false_positive",
            "new_approach",
        )
    ]
    + [
        ("disposition_assurance", v)
        for v in ("execution_proven", "human_reviewed", "machine_verified", "claimed")
    ]
    + [
        ("source_type", v)
        for v in (
            "mr_comment",
            "commit",
            "jira",
            "interactive",
            "triage_report",
            "validation_report",
            "rebaseline",
        )
    ]
    + [("review_item_status", v) for v in ("pending", "confirmed", "rejected")]
    + [("disposition_embargo", v) for v in ("required", "not_required", "uncertain", "active")]
    + [
        ("threat-likelihood", v)
        for v in ("very_rare", "rare", "possible", "likely", "almost_certain")
    ]
    + [("threat-impact", "existential")]
    + [
        ("threat-status", v)
        for v in ("unmitigated", "partially_mitigated", "mitigated", "risk_accepted")
    ]
    + [
        ("ref_kind", "default"),
        ("ownership", "external-bu"),
        ("ownership", "harness-qa"),
        ("patch_evidence_kind", "regression"),
        ("isolation_check_result", "na"),
    ]
)

# Rows of the mapping table that are not v1 enum values, so value aliases do
# not carry them. Each names the plan step that handles it instead.
NOT_VALUE_CONVERSIONS = {
    "vote_breakdown key cannot_verify": "a JSON key, not a value; step 17 maps it",
    "refuted-register tier": "a free-text field today; step 17 turns it into an enum",
    "report validation_status": "a duplicate field that step 18 removes from the schema",
}


def fixtures() -> dict[str, dict]:
    return enum_v2.load_dir(FIXTURES)


def test_meta_schema_is_valid():
    schema = json.loads(enum_v2.FORMAT.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)


def test_fixture_set_passes_every_rule():
    assert enum_v2.problems(fixtures(), V1) == []


def test_real_v2_files_pass_every_rule():
    assert enum_v2.problems(enum_v2.load_dir(enum_v2.V2_DIR), V1) == []


def test_every_assessment_conversion_is_expressed():
    aliased = {
        (a["from"]["enum"], a["from"]["value"])
        for f in fixtures().values()
        for a in f["aliases_from_v1"]
    }
    missing = [row for row in ASSESSMENT_ROWS if row not in aliased]
    assert not missing, f"mapping-table rows with no alias: {missing}"
    assert all(reason for reason in NOT_VALUE_CONVERSIONS.values())


def test_fixtures_use_every_kind_of_conversion():
    aliases = [a for f in fixtures().values() for a in f["aliases_from_v1"]]

    def kinds(a):
        return {next(iter(e)) if "enum" not in e else "enum" for e in a["to"]}

    assert any(
        a["from"]["value"] != a["to"][0].get("value") and len(a["to"]) == 1 for a in aliases
    ), "rename"
    merged = {}
    for a in aliases:
        if len(a["to"]) == 1 and "enum" in a["to"][0]:
            merged.setdefault((a["to"][0]["enum"], a["to"][0]["value"]), set()).add(
                (a["from"]["enum"], a["from"]["value"])
            )
    assert any(len(srcs) > 1 for srcs in merged.values()), "merge"
    assert any(sum(1 for e in a["to"] if "enum" in e) > 1 for a in aliases), "split"
    assert any("when" in a for a in aliases), "conditional"
    assert any("set" in kinds(a) for a in aliases), "set a non-vocabulary field"
    assert any("drop" in kinds(a) for a in aliases), "drop"


def _minimal() -> dict[str, dict]:
    """A two-file set that passes, used as the base for each negative case."""
    return {
        "colour.json": {
            "name": "colour",
            "description": "What colour is it?",
            "values": ["red", "blue"],
            "definitions": {"red": "Red.", "blue": "Blue."},
            "standard": {"none": "Test vocabulary."},
            "since": "0.0.1",
            "replaces_v1": ["actor_kind"],
            "aliases_from_v1": [
                {
                    "from": {"enum": "actor_kind", "value": "human"},
                    "when": [{"field": "note", "matches": "^x"}],
                    "to": [{"enum": "colour", "value": "blue"}],
                },
                {
                    "from": {"enum": "actor_kind", "value": "human"},
                    "to": [{"enum": "colour", "value": "red"}, {"enum": "shade", "value": "dark"}],
                },
                {"from": {"enum": "actor_kind", "value": "machine"}, "to": [{"drop": "Gone."}]},
            ],
        },
        "shade.json": {
            "name": "shade",
            "description": "How dark is it?",
            "values": ["dark", "light"],
            "definitions": {"dark": "Dark.", "light": "Light."},
            "standard": {"name": "Test standard", "relationship": "exact"},
            "since": "0.0.1",
            "replaces_v1": [],
            "aliases_from_v1": [],
        },
    }


def test_minimal_set_passes():
    assert enum_v2.problems(_minimal(), V1) == []


def _break(mutate) -> list[str]:
    files = copy.deepcopy(_minimal())
    mutate(files)
    return enum_v2.problems(files, V1)


@pytest.mark.parametrize(
    ("case", "mutate", "expected"),
    [
        (
            "definitions must cover values",
            lambda f: f["colour.json"]["definitions"].pop("blue"),
            "definitions missing ['blue']",
        ),
        (
            "every v1 value needs an unconditional alias",
            lambda f: f["colour.json"]["aliases_from_v1"].pop(2),
            "v1 actor_kind.machine has no unconditional alias",
        ),
        (
            "only one unconditional alias per v1 value",
            lambda f: f["colour.json"]["aliases_from_v1"].append(
                {"from": {"enum": "actor_kind", "value": "machine"}, "to": [{"drop": "Again."}]}
            ),
            "second unconditional alias for actor_kind.machine",
        ),
        (
            "conditional aliases must come first",
            lambda f: f["colour.json"]["aliases_from_v1"].reverse(),
            "comes after its unconditional alias",
        ),
        (
            "targets must exist",
            lambda f: f["colour.json"]["aliases_from_v1"][1]["to"].__setitem__(
                0, {"enum": "colour", "value": "green"}
            ),
            "'green' is not a value of v2 'colour'",
        ),
        (
            "sources must be real v1 values",
            lambda f: f["colour.json"]["aliases_from_v1"][2]["from"].__setitem__("value", "robot"),
            "'robot' is not a value of v1 'actor_kind'",
        ),
        (
            "a v1 enum has one owner",
            lambda f: f["shade.json"]["replaces_v1"].append("actor_kind"),
            "is also replaced by",
        ),
        (
            "an adapted standard needs a note",
            lambda f: f["shade.json"].__setitem__(
                "standard", {"name": "X", "relationship": "adapted"}
            ),
            "adapted standard needs a note",
        ),
        (
            "an alias sets a vocabulary once",
            lambda f: f["colour.json"]["aliases_from_v1"][1]["to"].append(
                {"enum": "shade", "value": "light"}
            ),
            "sets 'shade' twice",
        ),
        (
            "file name follows the enum name",
            lambda f: f.__setitem__("hue.json", f.pop("shade.json")),
            "file name should be shade.json",
        ),
        (
            "regexes must compile",
            lambda f: f["colour.json"]["aliases_from_v1"][0]["when"][0].__setitem__(
                "matches", "(unclosed"
            ),
            "is not a 'regex'",
        ),
        (
            "the shape is checked by the meta-schema",
            lambda f: f["shade.json"].pop("standard"),
            "'standard' is a required property",
        ),
    ],
)
def test_each_rule_rejects_a_violation(case, mutate, expected):
    found = _break(mutate)
    assert any(expected in p for p in found), f"{case}: got {found}"
