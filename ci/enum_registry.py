#!/usr/bin/env python3
"""Enum registry: derive and check the metadata in enums/v1 from the schemas.

The enum files in enums/v1 are the registry of controlled vocabularies. Two of
their fields describe where a vocabulary lives, and both used to be written by
hand, which let them drift from the schemas (a `source_schema` naming a file
that does not exist, a `used_in_schemas` claiming a schema that defines a
different enum under the same name). This module derives them instead.

A schema *site* is any JSON Schema node whose `enum` holds two or more string
values. `null` is ignored when comparing value sets, so a nullable site and a
non-nullable site with the same strings are the same vocabulary. Nodes inside
an `if` subschema are conditions over values defined elsewhere, not
definitions, and are skipped. Numeric enums (format-version switches) are out
of scope.

A registered enum is *used in* a schema when validating that schema can reach
a site with the enum's exact value set, directly or through `$ref` chains
across files. A vocabulary that is documented but deliberately not enforced by
any schema enum (its source node is prose or a pattern) sets
`"schema_enforced": false`; it is then used where its `source_schema` points.

  (no flag)   print the unregistered sites and exit 0 (warn mode)
  --check     exit 1 when any registered file's metadata is wrong
  --write     rewrite `used_in_schemas` in every registered file
  --enforce   with --check, also exit 1 when any site is unregistered
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIRS = (ROOT / "schemas" / "v1", ROOT / "config" / "v1")
ENUMS_DIR = ROOT / "enums" / "v1"


@dataclass(frozen=True)
class Site:
    schema: str
    pointer: str
    values: frozenset[str]

    @property
    def ref(self) -> str:
        return f"{self.schema}#{self.pointer}"


def _escape(segment: str) -> str:
    return segment.replace("~", "~0").replace("/", "~1")


def _unescape(segment: str) -> str:
    return segment.replace("~1", "/").replace("~0", "~")


def load_schemas() -> dict[str, dict]:
    schemas: dict[str, dict] = {}
    for directory in SCHEMA_DIRS:
        for path in sorted(directory.glob("*.schema.json")):
            if path.name in schemas:
                raise SystemExit(f"duplicate schema file name across dirs: {path.name}")
            schemas[path.name] = json.loads(path.read_text(encoding="utf-8"))
    return schemas


def _string_values(node: dict) -> frozenset[str] | None:
    raw = node.get("enum")
    if not isinstance(raw, list):
        return None
    strings = [v for v in raw if isinstance(v, str)]
    if len(strings) < 2 or any(v is not None and not isinstance(v, str) for v in raw):
        return None
    return frozenset(strings)


def _walk(node, pointer: str, in_if: bool):
    if isinstance(node, dict):
        yield node, pointer, in_if
        for key, child in node.items():
            yield from _walk(child, f"{pointer}/{_escape(key)}", in_if or key == "if")
    elif isinstance(node, list):
        for i, child in enumerate(node):
            yield from _walk(child, f"{pointer}/{i}", in_if)


def iter_sites(schemas: dict[str, dict]) -> list[Site]:
    sites = []
    for name, schema in schemas.items():
        for node, pointer, in_if in _walk(schema, "", False):
            values = _string_values(node)
            if values is not None and not in_if:
                sites.append(Site(name, pointer, values))
    return sites


def resolve(schemas: dict[str, dict], ref: str, base: str) -> tuple[str, dict] | None:
    """Resolve a `$ref` (relative file + JSON pointer) to (schema name, node)."""
    file_part, _, fragment = ref.partition("#")
    target = file_part or base
    node = schemas.get(target)
    if node is None:
        return None
    for segment in (s for s in fragment.split("/") if s):
        segment = _unescape(segment)
        if isinstance(node, dict) and segment in node:
            node = node[segment]
        elif isinstance(node, list) and segment.isdigit() and int(segment) < len(node):
            node = node[int(segment)]
        else:
            return None
    return target, node


def reachable(schemas: dict[str, dict]) -> dict[str, set[frozenset[str]]]:
    """Value sets each schema validates, following `$ref` chains across files."""
    memo: dict[int, set[frozenset[str]]] = {}

    def collect(node, base: str, stack: frozenset[int]) -> set[frozenset[str]]:
        key = id(node)
        if key in memo:
            return memo[key]
        if key in stack:
            return set()
        stack = stack | {key}
        found: set[frozenset[str]] = set()
        for sub, _pointer, in_if in _walk(node, "", False):
            if in_if:
                continue
            values = _string_values(sub)
            if values is not None:
                found.add(values)
            ref = sub.get("$ref")
            if isinstance(ref, str):
                hit = resolve(schemas, ref, base)
                if hit is not None:
                    found |= collect(hit[1], hit[0], stack)
        memo[key] = found
        return found

    return {name: collect(schema, name, frozenset()) for name, schema in schemas.items()}


def load_registry() -> dict[str, dict]:
    return {
        path.name: json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(ENUMS_DIR.glob("*.json"))
    }


def derived_used_in(values: frozenset[str], reach: dict[str, set[frozenset[str]]]) -> list[str]:
    return sorted(name for name, sets in reach.items() if values in sets)


def problems(schemas: dict[str, dict], registry: dict[str, dict]) -> list[str]:
    """Every way a registered file's metadata disagrees with the schemas."""
    reach = reachable(schemas)
    out: list[str] = []
    seen_sets: dict[frozenset[str], str] = {}
    seen_names: dict[str, str] = {}
    for fname, entry in registry.items():
        values = frozenset(entry.get("values") or [])
        name = entry.get("name")
        if name in seen_names:
            out.append(f"{fname}: name {name!r} already used by {seen_names[name]}")
        seen_names[name] = fname
        if values in seen_sets:
            out.append(f"{fname}: same value set as {seen_sets[values]}")
        seen_sets[values] = fname

        source = entry.get("source_schema") or ""
        enforced = entry.get("schema_enforced", True)
        if source:
            hit = resolve(schemas, source, "") if "#" in source else None
            if hit is None:
                out.append(f"{fname}: source_schema {source!r} does not resolve")
            elif enforced and _string_values(hit[1]) != values:
                out.append(f"{fname}: source_schema {source!r} values differ from the file")
            elif not enforced and _string_values(hit[1]) is not None:
                out.append(f"{fname}: schema_enforced is false but {source!r} is an enum")

        derived = _used_in(entry, reach)
        if source and enforced and not derived:
            out.append(f"{fname}: no schema site carries this value set")
        declared = entry.get("used_in_schemas")
        if declared is not None and sorted(declared) != derived:
            out.append(f"{fname}: used_in_schemas {sorted(declared)} != derived {derived}")
    return out


def _used_in(entry: dict, reach: dict[str, set[frozenset[str]]]) -> list[str]:
    """Documented-only vocabularies (`schema_enforced: false`) live where their
    source points; enforced ones wherever their exact value set is validated."""
    if entry.get("schema_enforced", True) is False:
        source = entry.get("source_schema") or ""
        return [source.partition("#")[0]] if source else []
    return derived_used_in(frozenset(entry.get("values") or []), reach)


def unregistered(schemas: dict[str, dict], registry: dict[str, dict]) -> list[Site]:
    registered = {
        frozenset(e.get("values") or [])
        for e in registry.values()
        if e.get("schema_enforced", True) is not False
    }
    return [s for s in iter_sites(schemas) if s.values not in registered]


def _dump(entry: dict, ensure_ascii: bool) -> str:
    return json.dumps(entry, indent=2, ensure_ascii=ensure_ascii) + "\n"


def write(schemas: dict[str, dict]) -> int:
    reach = reachable(schemas)
    changed = 0
    for path in sorted(ENUMS_DIR.glob("*.json")):
        raw = path.read_text(encoding="utf-8")
        entry = json.loads(raw)
        ensure_ascii = _dump(entry, True) == raw or raw.isascii()
        derived = _used_in(entry, reach)
        if entry.get("used_in_schemas") != derived:
            entry["used_in_schemas"] = derived
            path.write_text(_dump(entry, ensure_ascii), encoding="utf-8")
            changed += 1
    return changed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    parser.add_argument("--enforce", action="store_true")
    args = parser.parse_args(argv)

    schemas = load_schemas()
    if args.write:
        print(f"rewrote used_in_schemas in {write(schemas)} file(s)")
        return 0

    registry = load_registry()
    loose = unregistered(schemas, registry)
    for site in loose:
        print(f"unregistered: {site.ref} {sorted(site.values)}")
    print(f"{len(loose)} unregistered site(s), {len({s.values for s in loose})} value set(s)")
    if not args.check:
        return 0
    found = problems(schemas, registry)
    for problem in found:
        print(f"registry: {problem}", file=sys.stderr)
    return 1 if found or (args.enforce and loose) else 0


if __name__ == "__main__":
    sys.exit(main())
