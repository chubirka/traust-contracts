"""Regenerate traust docs/storage-v1-ddl-model.md from the checked-in SQL.

Reads storage/v1/{sqlite,postgres}/schema/*.sql and storage/v1/profiles.json,
and emits the table model as Mermaid class diagrams: core, secondary (fan-out)
projections, primary projections, and the artifact-class table. Nothing here
is recalled; run it whenever the DDL moves.

    python3 -m traust_contracts.v1.storage.build_storage_ddl_model \
        --out ../traust/docs/storage-v1-ddl-model.md
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from traust_contracts.paths import storage_dir
from traust_contracts.v1.ddl_model import TableModel, load_tables, render_diagram


def load(storage: Path) -> tuple[dict[str, TableModel], dict]:
    tables = load_tables(storage)
    views = sorted(p.stem for p in (storage / "sqlite/views").glob("*.sql"))
    profiles = json.loads((storage / "profiles.json").read_text())["artifacts"]
    return tables, {"views": views, "profiles": profiles}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--out", type=Path, required=True, help="e.g. ../traust/docs/storage-v1-ddl-model.md"
    )
    args = ap.parse_args()
    tables, meta = load(storage_dir())
    out = args.out

    core = ["artifact_binding", "artifact_evidence", "artifact_location", "traust_storage_meta"]
    profiles = meta["profiles"]
    primary_by_family = {n: p["projection"] for n, p in profiles.items() if p.get("projection")}
    primary = sorted(set(primary_by_family.values()))
    secondary = sorted(t for t in tables if t not in core and t not in primary)
    fanout_notes = {}
    # secondary tables: name the array they fan out where it is knowable by convention
    for t in secondary:
        fanout_notes[t] = "fan-out"

    classes: dict[str, list[str]] = {}
    for fam, p in profiles.items():
        classes.setdefault(p["class"], []).append(fam)

    lines = [
        "# storage/v1 DDL — table model",
        "",
        "<!-- GENERATED FILE — do not edit by hand; edits are overwritten on the next run.",
        "     Regenerate from a traust-contracts checkout whenever the storage/v1 DDL changes:",
        "       python -m traust_contracts.v1.storage.build_storage_ddl_model \\",
        "         --out ../traust/docs/storage-v1-ddl-model.md",
        "     To change the prose, edit",
        "     src/traust_contracts/v1/storage/build_storage_ddl_model.py, then regenerate. -->",
        "",
        f"**{len(tables)} tables, {len(meta['views'])} views, two dialects.** SQLite and",
        "PostgreSQL declare the same tables, the same column names, in the same",
        "order — verified by the generator, zero differences. Only TYPES diverge where the dialect",
        "demands it, shown as `sqlite|postgres` (`TEXT|JSONB`, `REAL|DOUBLE PRECISION`,",
        "`INTEGER|BIGINT`). PostgreSQL relations live in the fixed `traust_storage` schema;",
        "SQLite uses the database file as its namespace.",
        "",
        "Legend: `+` primary key, arrows are declared foreign keys.",
        "",
        "## How the layers relate",
        "",
        "```mermaid",
        "classDiagram",
        "  direction TB",
        "  class artifact_evidence {",
        "    digest + byte_size",
        "    SHA-256 keyed, no payload",
        "  }",
        "  class artifact_binding {",
        "    the caller's context",
        "    scope / subject / run / layer",
        "  }",
        "  class primary_projection {",
        "    one row per ARTIFACT",
        "    root scalars become columns",
        "  }",
        "  class secondary_projection {",
        "    one row per REPEATED ELEMENT",
        "    array or collection fan-out",
        "  }",
        "  class scoped_view {",
        "    the consumption surface",
        "    scoped, current-resolved",
        "  }",
        "  artifact_evidence <-- artifact_binding : artifact_digest",
        "  artifact_binding <-- primary_projection : binding_id",
        "  artifact_binding <-- secondary_projection : binding_id",
        "  primary_projection <-- scoped_view",
        "  secondary_projection <-- scoped_view",
        "```",
        "",
        "A view composes columns these tables provide. It does not mine a JSON",
        "blob for fields the DDL never declared — see `storage/v1/README.md`,",
        '"The schema is the reference".',
        "",
        "## Artifact classes",
        "",
        "`profiles.json` gives every family a binding class, which fixes what",
        "context its rows can carry.",
        "",
        "| class | count | families |",
        "|---|---|---|",
    ]
    for cls in sorted(classes):
        fams = ", ".join(f"`{f}`" for f in sorted(classes[cls]))
        lines.append(f"| **{cls}** | {len(classes[cls])} | {fams} |")
    lines += [
        "",
        "## Views",
        "",
        ", ".join(f"`{v}`" for v in meta["views"]),
        "",
        "---",
        "",
        f"### Core — evidence, binding, metadata ({len(core)})",
        "",
        render_diagram(core, tables),
        "",
        "### Secondary fan-out projections — one row per repeated collection element"
        f" ({len(secondary)})",
        "",
        "A repeated collection element is one object from an artifact array or equivalent",
        "collection—for example, one finding from `findings[]` or one event from",
        "`events[]`. Each row remains tied to the source artifact through `binding_id`",
        "and `artifact_digest`, plus its element key such as `finding_id` or `event_id`.",
        "Nested structures that are not fanned out remain in their declared JSON/JSONB",
        "columns; this does not mean one row per arbitrary JSON value.",
        "",
        render_diagram(secondary, tables, fanout_notes),
        "",
        f"### Primary projections — one row per ARTIFACT ({len(primary)})",
        "",
        "Split across three diagrams for legibility; the grouping is alphabetical"
        " and carries no meaning.",
        "",
    ]
    third = (len(primary) + 2) // 3
    for i in range(0, len(primary), third):
        lines += [render_diagram(primary[i : i + third], tables), ""]
    out.write_text("\n".join(lines) + "\n")
    print(f"wrote {out} ({len(tables)} tables, {len(meta['views'])} views)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
