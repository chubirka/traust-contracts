#!/usr/bin/env python3
"""Check a set of v2 registry enums against the format and the v1 registry.

The JSON Schema in enums/format/v2.schema.json checks each file's shape. This
module checks what a schema cannot:

- `definitions` covers exactly the file's `values`.
- The file is named after its `name`, and names are unique across the set.
- Every v1 enum in a `replaces_v1` list exists, and is owned by one v2 file.
- Every `from` names an owned v1 enum and one of its values.
- Every value of every owned v1 enum has exactly one unconditional alias,
  and any conditional aliases for it come before that one.
- Every enum effect names a v2 enum in the set and one of its values.
- No alias sets the same vocabulary or field twice.

  python3 ci/enum_v2.py [--dir enums/v2]   exit 1 on any problem
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parent.parent
FORMAT = ROOT / "enums" / "format" / "v2.schema.json"
V1_DIR = ROOT / "enums" / "v1"
V2_DIR = ROOT / "enums" / "v2"


def load_dir(directory: Path) -> dict[str, dict]:
    return {
        p.name: json.loads(p.read_text(encoding="utf-8")) for p in sorted(directory.glob("*.json"))
    }


def v1_values(v1_dir: Path = V1_DIR) -> dict[str, list[str]]:
    return {e["name"]: e["values"] for e in load_dir(v1_dir).values()}


def problems(files: dict[str, dict], v1: dict[str, list[str]]) -> list[str]:
    out: list[str] = []
    validator = jsonschema.Draft202012Validator(
        json.loads(FORMAT.read_text(encoding="utf-8")),
        format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER,
    )
    valid: dict[str, dict] = {}
    for fname, entry in files.items():
        errors = sorted(validator.iter_errors(entry), key=lambda e: list(e.path))
        for err in errors:
            where = "/".join(str(p) for p in err.path) or "(root)"
            out.append(f"{fname}: {where}: {err.message}")
        if not errors:
            valid[fname] = entry

    by_name: dict[str, dict] = {}
    owner: dict[str, str] = {}
    for fname, entry in valid.items():
        name = entry["name"]
        if fname != name.replace("_", "-") + ".json":
            out.append(f"{fname}: file name should be {name.replace('_', '-')}.json")
        if name in by_name:
            out.append(f"{fname}: name {name!r} is used twice")
        by_name[name] = entry
        if set(entry["definitions"]) != set(entry["values"]):
            missing = sorted(set(entry["values"]) - set(entry["definitions"]))
            extra = sorted(set(entry["definitions"]) - set(entry["values"]))
            out.append(f"{fname}: definitions missing {missing}, extra {extra}")
        std = entry["standard"]
        if std.get("relationship") == "adapted" and not std.get("note"):
            out.append(f"{fname}: an adapted standard needs a note saying what differs")
        for v1_name in entry["replaces_v1"]:
            if v1_name not in v1:
                out.append(f"{fname}: replaces_v1 names unknown v1 enum {v1_name!r}")
            elif v1_name in owner:
                out.append(f"{fname}: v1 enum {v1_name!r} is also replaced by {owner[v1_name]}")
            else:
                owner[v1_name] = fname

    for fname, entry in valid.items():
        seen_unconditional: dict[tuple[str, str], int] = {}
        conditional_after: set[tuple[str, str]] = set()
        for i, alias in enumerate(entry["aliases_from_v1"]):
            src = (alias["from"]["enum"], alias["from"]["value"])
            if src[0] not in entry["replaces_v1"]:
                out.append(
                    f"{fname}: alias {i} converts {src[0]!r}, which this file does not replace"
                )
            elif src[1] not in v1.get(src[0], []):
                out.append(f"{fname}: alias {i}: {src[1]!r} is not a value of v1 {src[0]!r}")
            if "when" in alias:
                # `matches` regexes are validated by the meta-schema's format check.
                if src in seen_unconditional:
                    conditional_after.add(src)
            elif src in seen_unconditional:
                out.append(
                    f"{fname}: alias {i}: second unconditional alias for {src[0]}.{src[1]} "
                    f"(first is alias {seen_unconditional[src]})"
                )
            else:
                seen_unconditional[src] = i
            targets: set[str] = set()
            for effect in alias["to"]:
                key = (
                    f"enum:{effect['enum']}"
                    if "enum" in effect
                    else f"set:{effect['set']['field']}"
                    if "set" in effect
                    else None
                )
                if key and key in targets:
                    out.append(f"{fname}: alias {i} sets {key.split(':', 1)[1]!r} twice")
                if key:
                    targets.add(key)
                if "enum" in effect:
                    target = by_name.get(effect["enum"])
                    if target is None:
                        out.append(f"{fname}: alias {i}: unknown v2 enum {effect['enum']!r}")
                    elif effect["value"] not in target["values"]:
                        out.append(
                            f"{fname}: alias {i}: {effect['value']!r} is not a value of "
                            f"v2 {effect['enum']!r}"
                        )
        for src in sorted(conditional_after):
            out.append(
                f"{fname}: a conditional alias for {src[0]}.{src[1]} comes after its "
                "unconditional alias and can never apply"
            )
        for v1_name in entry["replaces_v1"]:
            for value in v1.get(v1_name, []):
                if (v1_name, value) not in seen_unconditional:
                    out.append(f"{fname}: v1 {v1_name}.{value} has no unconditional alias")
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--dir", type=Path, default=V2_DIR)
    args = parser.parse_args(argv)
    files = load_dir(args.dir)
    found = problems(files, v1_values())
    for problem in found:
        print(problem, file=sys.stderr)
    print(f"{len(files)} v2 file(s), {len(found)} problem(s)")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
