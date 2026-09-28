"""Registry gate: enums/v1 metadata must be derivable from the schemas.

`source_schema` and `used_in_schemas` were hand-written and drifted (a source
naming a schema file that does not exist, a usage list claiming a schema that
defines a different enum). ci/enum_registry.py derives them; this test fails
when a registered file disagrees with what it derives.

Schema enums with no registered file are reported as a warning for now. Once
every inline enum is registered, the warning becomes a failure.
"""

from __future__ import annotations

import importlib.util
import sys
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("enum_registry", ROOT / "ci" / "enum_registry.py")
enum_registry = importlib.util.module_from_spec(_spec)
sys.modules["enum_registry"] = enum_registry  # dataclasses resolve annotations via sys.modules
_spec.loader.exec_module(enum_registry)


def test_registry_metadata_matches_schemas():
    found = enum_registry.problems(enum_registry.load_schemas(), enum_registry.load_registry())
    assert not found, "run `python3 ci/enum_registry.py --write`, then fix:\n" + "\n".join(found)


def test_unregistered_schema_enums_are_reported():
    loose = enum_registry.unregistered(enum_registry.load_schemas(), enum_registry.load_registry())
    if loose:
        sets = len({site.values for site in loose})
        warnings.warn(
            f"{len(loose)} schema enum site(s) ({sets} value sets) have no enums/v1 file; "
            "list them with `python3 ci/enum_registry.py`",
            stacklevel=1,
        )


def test_resolve_follows_json_pointer_escapes():
    schemas = {"a.schema.json": {"$defs": {"x/y": {"enum": ["p", "q"]}}}}
    hit = enum_registry.resolve(schemas, "a.schema.json#/$defs/x~1y", "")
    assert hit is not None
    assert enum_registry._string_values(hit[1]) == frozenset({"p", "q"})


def test_usage_follows_refs_across_files():
    schemas = {
        "a.schema.json": {"$defs": {"level": {"enum": ["low", "high"]}}},
        "b.schema.json": {"properties": {"s": {"$ref": "a.schema.json#/$defs/level"}}},
        "c.schema.json": {"properties": {"t": {"$ref": "b.schema.json#/properties/s"}}},
        "d.schema.json": {"if": {"properties": {"s": {"enum": ["low", "high"]}}}},
    }
    reach = enum_registry.reachable(schemas)
    used = enum_registry.derived_used_in(frozenset({"low", "high"}), reach)
    # d only names the values inside an `if` condition; it does not validate them.
    assert used == ["a.schema.json", "b.schema.json", "c.schema.json"]
