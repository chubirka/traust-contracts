"""
Tests for traust-contracts schema integrity.

The golden-vector tests were removed with the suite on 2026-08-18. The recipe's
regression fixtures live in the ledger package, beside the implementation they
guard.
"""

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError
from referencing import Registry, Resource

REPO_ROOT = Path(__file__).parent.parent
SCHEMA_DIR = REPO_ROOT / "schemas" / "v1"
CONFIG_SCHEMA_DIR = REPO_ROOT / "config" / "v1"
ENUMS_DIR = REPO_ROOT / "enums" / "v1"


def build_registry() -> Registry:
    """Build $ref registry across all schemas."""
    resources = {}
    for sf in sorted(SCHEMA_DIR.glob("*.schema.json")):
        doc = json.loads(sf.read_text(encoding="utf-8"))
        schema_id = doc.get("$id", sf.name)
        resources[schema_id] = Resource.from_contents(doc)
    return Registry(resources=resources)


def test_complete_synthetic_layer_document() -> None:
    """The portable schema validates a whole layer, not just isolated events."""
    from jsonschema import FormatChecker

    schema = json.loads((SCHEMA_DIR / "layer.schema.json").read_text(encoding="utf-8"))
    document = json.loads(
        (REPO_ROOT / "tests/fixtures/sample-findings-layer.json").read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    validator.validate(document)
    assert len(document["events"]) == 2
    assert "\0" in document["events"][0]["rationale"]
    for field in ("metadata", "events", "needs_review"):
        with pytest.raises(ValidationError):
            validator.validate({key: value for key, value in document.items() if key != field})


class TestSchemas:
    """Schema parsing and validation tests."""

    def test_all_schemas_parse_json(self):
        """All schema files must be valid JSON."""
        schema_files = list(SCHEMA_DIR.glob("*.schema.json"))
        assert len(schema_files) == 31, f"Expected 31 data schemas, found {len(schema_files)}"

        config_schema_files = list(CONFIG_SCHEMA_DIR.glob("*.schema.json"))
        assert len(config_schema_files) == 13, (
            f"Expected 13 config schemas, found {len(config_schema_files)}"
        )

        for sf in [*schema_files, *config_schema_files]:
            with Path(sf).open() as f:
                try:
                    json.load(f)
                except json.JSONDecodeError as e:
                    pytest.fail(f"{sf.name}: invalid JSON: {e}")

    def test_all_schemas_are_valid_draft202012(self):
        """All schemas can be instantiated as Draft 2020-12 validators."""
        registry = build_registry()

        for sf in sorted(SCHEMA_DIR.glob("*.schema.json")):
            schema = json.loads(sf.read_text(encoding="utf-8"))
            try:
                # Verify the schema can be instantiated as a validator
                Draft202012Validator(schema, registry=registry)
            except Exception as e:
                pytest.fail(f"{sf.name}: failed to instantiate validator: {e}")

    def test_refs_resolve(self):
        """Cross-file $refs must resolve."""
        registry = build_registry()

        # Try to resolve a known cross-file ref as smoke test
        # (e.g., if report.schema.json has a $ref to another schema)
        report_schema = json.loads((SCHEMA_DIR / "report.schema.json").read_text())
        validator = Draft202012Validator(report_schema, registry=registry)

        # Create a minimal valid report to trigger ref resolution
        minimal_report = {
            "title": "Security Assessment",
            "metadata": {"date": "2026-01-01", "scope": "test"},
            "executive_summary": "Test",
            "severity_criteria": [
                {"level": "critical", "description": "Test"},
                {"level": "high", "description": "Test"},
                {"level": "medium", "description": "Test"},
                {"level": "low", "description": "Test"},
            ],
            "findings": [],
            "findings_summary": [
                {"severity": "critical", "count": 0},
                {"severity": "high", "count": 0},
                {"severity": "medium", "count": 0},
                {"severity": "low", "count": 0},
            ],
            "remediation_roadmap": [{"phase": 1, "description": "Test"}],
        }

        # Should not raise during validation (refs should resolve)
        list(validator.iter_errors(minimal_report))


class TestEnums:
    """Enum vocabulary consistency tests."""

    def test_enums_directory_exists(self):
        """enums/ directory should exist."""
        assert ENUMS_DIR.exists(), f"Enums directory not found: {ENUMS_DIR}"

    def test_enum_files_parse(self):
        """All enum files must be valid JSON."""
        enum_files = list(ENUMS_DIR.glob("*.json"))
        assert len(enum_files) > 0, "No enum files found"

        for ef in enum_files:
            with Path(ef).open() as f:
                try:
                    json.load(f)
                except json.JSONDecodeError as e:
                    pytest.fail(f"{ef.name}: invalid JSON: {e}")

    def test_enum_values_in_source_schemas(self):
        """Each enum's values must appear verbatim in its source schema."""
        for ef in sorted(ENUMS_DIR.glob("*.json")):
            with Path(ef).open() as f:
                enum_def = json.load(f)

            source = enum_def.get("source_schema", "")
            if not source:
                continue
            parts = source.split("#")
            if len(parts) != 2:
                continue

            schema_name, json_path = parts
            schema_file = SCHEMA_DIR / schema_name
            if not schema_file.exists():
                continue

            with Path(schema_file).open() as f:
                schema = json.load(f)

            # Navigate to the enum definition
            obj = schema
            for segment in json_path.strip("/").split("/"):
                if segment.startswith("$"):
                    obj = obj.get(segment, {})
                elif segment in obj:
                    obj = obj[segment]
                else:
                    # Path not found, skip validation
                    break
            else:
                # Successfully navigated; check enum values
                if isinstance(obj, dict) and "enum" in obj:
                    # null marks a nullable field, not a vocabulary value; the
                    # registry records strings only (ci/enum_registry.py).
                    schema_values = {v for v in obj["enum"] if v is not None}
                    enum_values = set(enum_def.get("values", []))
                    assert enum_values == schema_values, (
                        f"{ef.name}: values mismatch with {schema_name}. "
                        f"Expected {schema_values}, got {enum_values}"
                    )

    def test_layer_review_queue_reason_matches_schema(self):
        enum_path = ENUMS_DIR / "layer-review-queue-reason.json"
        enum_def = json.loads(enum_path.read_text(encoding="utf-8"))
        layer = json.loads((SCHEMA_DIR / "layer.schema.json").read_text(encoding="utf-8"))
        schema_values = set(layer["$defs"]["review_item"]["properties"]["queue_reason"]["enum"])
        assert set(enum_def["values"]) == schema_values

    def test_triage_verdict_matches_schema(self):
        enum_def = json.loads((ENUMS_DIR / "verdict.json").read_text(encoding="utf-8"))
        triage = json.loads((SCHEMA_DIR / "triage.schema.json").read_text(encoding="utf-8"))
        assert set(enum_def["values"]) == set(triage["$defs"]["verdict"]["enum"])

    def test_stamped_event_validates(self):
        """An event carrying its identity stamp must validate.

        $defs.event is additionalProperties: false, and the ledger write path
        (events.attach_identity) stamps fingerprint/fingerprint_algo
        onto every event it writes. Between 0.3.0 and 0.4.2 the schema did not
        declare either field, so every stamped layer file failed validation —
        49 files / 198 events in the test corpus before this was
        caught. Keep both fields declared.
        """
        layer = json.loads((SCHEMA_DIR / "layer.schema.json").read_text(encoding="utf-8"))
        event_schema = {**layer["$defs"]["event"], "$defs": layer["$defs"]}
        stamped = {
            "event_id": "a" * 64,
            "finding_ref": "FIND-001",
            "recorded_at": "2026-08-17T00:00:00+00:00",
            "source": {
                "type": "interactive",
                "ref": "interactive:2026-08-17:embargo:required",
                "actor": {"kind": "human", "identity": "analyst@example.com"},
            },
            "disposition": {"validity": "confirmed"},
            "rationale": "stamped by the ledger write path",
            "fingerprint": "b" * 64,
            "fingerprint_algo": "v1",
        }
        errors = list(Draft202012Validator(event_schema).iter_errors(stamped))
        assert not errors, [e.message for e in errors]


def test_every_findings_schema_declares_the_identity_fields():
    """A schema with findings and additionalProperties:false must declare
    both `fingerprint` and `fingerprint_algo`, or the stamped corpus it
    describes is invalid against it.

    This has now bitten twice. report.schema.json omitted fingerprint_algo
    while the producer emitted it, leaving thousands of audit reports invalid for
    16 days. cloud-config-findings-current.schema.json declared NEITHER, so
    stamping the policy findings turned nearly every valid report invalid in
    one command.
    """
    import json

    from traust_contracts.paths import schema_dir

    missing = []
    for path in sorted(schema_dir().glob("*.json")):
        document = json.loads(path.read_text())
        candidates = [
            (
                "properties.findings.items",
                document.get("properties", {}).get("findings", {}).get("items"),
            )
        ]
        candidates += [(f"$defs.{name}", node) for name, node in document.get("$defs", {}).items()]
        for where, node in candidates:
            if not isinstance(node, dict):
                continue
            properties = node.get("properties") or {}
            if "id" not in properties or "severity" not in properties:
                continue  # not a finding-shaped object
            if node.get("additionalProperties") is not False:
                continue
            for field in ("fingerprint", "fingerprint_algo"):
                if field not in properties:
                    missing.append(f"{path.name} {where}: {field}")
    assert not missing, (
        "finding-shaped objects missing an identity field; a stamped corpus "
        f"would be invalid against them: {missing}"
    )
