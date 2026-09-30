"""Compatibility gates for schema versioning.

Breaking-change gate: no property removal, enum shrinkage, or new required
fields versus the previous git tag.

The vector-hash gate that pinned the golden-vector suite to a deterministic
digest was removed with the suite itself on 2026-08-18 (only the harness computes
identity, so there is no second-language port for a shared oracle to hold). The
recipe's regression fixtures now live in the ledger package, beside the
implementation they guard.
"""

import json
import os
import subprocess
from pathlib import Path
from typing import Any, ClassVar

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = REPO_ROOT / "schemas" / "v1"


class TestBreakingChangeDetection:
    """Detect schema evolution breaking backward compatibility."""

    @staticmethod
    def _get_latest_tag() -> str:
        """Return the latest git tag (e.g., 'v0.1.0')."""
        try:
            result = subprocess.run(
                ["git", "describe", "--tags", "--abbrev=0"],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                check=True,
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            return None

    @staticmethod
    def _extract_json_pointer_path(path_list: list) -> str:
        """Convert a path list to JSON pointer notation."""
        return "/" + "/".join(str(p) for p in path_list)

    @staticmethod
    def _walk_schema(schema: dict, path: list) -> list:
        """Yield (json_pointer, schema_node) for all nodes in schema."""
        results = []

        def walk(node: Any, current_path: list):
            if isinstance(node, dict):
                pointer = "/" + "/".join(str(p) for p in current_path) if current_path else ""
                results.append((pointer, node))
                for key, value in node.items():
                    if key not in ("$schema", "$id", "title", "description", "examples"):
                        walk(value, [*current_path, key])
            elif isinstance(node, list):
                for i, item in enumerate(node):
                    walk(item, [*current_path, i])

        walk(schema, path)
        return results

    @staticmethod
    def _collect_properties(node: dict) -> set:
        """Collect all property names from a schema node."""
        if "properties" in node and isinstance(node["properties"], dict):
            return set(node["properties"].keys())
        return set()

    @staticmethod
    def _collect_enum_values(node: dict) -> set:
        """Collect enum values from a schema node."""
        if "enum" in node and isinstance(node["enum"], list):
            return set(node["enum"])
        return set()

    @staticmethod
    def _collect_conditional_required(schema: dict) -> set:
        """Collect (json_pointer, frozenset[fields]) for every `required` that sits
        under a conditional construct — the paths the node-by-node diff cannot see
        when the whole construct is new."""
        found = set()
        # Only branches that IMPOSE obligations count. A requirement inside `if`
        # narrows which artifacts the rule applies to, so it can never invalidate
        # one — including it would bury the real signal in noise.
        enter = ("then", "else", "allOf", "anyOf", "oneOf", "dependentRequired", "dependentSchemas")

        def walk(node, path, under_conditional):
            if isinstance(node, dict):
                if under_conditional and isinstance(node.get("required"), list):
                    found.add(("/" + "/".join(str(p) for p in path), frozenset(node["required"])))
                for key, value in node.items():
                    if key == "if":
                        continue
                    walk(value, [*path, key], under_conditional or key in enter)
            elif isinstance(node, list):
                for i, item in enumerate(node):
                    walk(item, [*path, i], under_conditional)

        walk(schema, [], False)
        return found

    @staticmethod
    def _anyof_satisfied_by_old_required(current: dict, old: dict, pointer: str) -> bool:
        """True when `pointer` is a branch of an anyOf that every OLD artifact satisfies.

        An anyOf rejects only artifacts matching none of its branches. When
        every branch is a bare `{"required": [...]}` and one branch asks for
        nothing beyond what the OLD schema already required at the same node,
        every old artifact matches that branch, so the anyOf cannot invalidate
        one. Deliberately narrow: oneOf is excluded (matching two branches
        fails it), and so is any branch carrying more than `required`.
        """
        parts = pointer.strip("/").split("/")
        if len(parts) < 2 or parts[-2] != "anyOf":
            return False

        def resolve(schema: dict, segments: list[str]):
            node = schema
            for segment in segments:
                if isinstance(node, list) and segment.isdigit():
                    node = node[int(segment)]
                elif isinstance(node, dict) and segment in node:
                    node = node[segment]
                else:
                    return None
            return node

        parent_path = parts[:-2]
        branches = resolve(current, [*parent_path, "anyOf"])
        old_parent = resolve(old, parent_path)
        if not isinstance(branches, list) or not isinstance(old_parent, dict):
            return False
        if not all(isinstance(b, dict) and set(b) == {"required"} for b in branches):
            return False
        old_required = set(old_parent.get("required") or [])
        return any(set(b["required"]) <= old_required for b in branches)

    @staticmethod
    def _defs_reachable_only_via_new_properties(current: dict, old: dict) -> set:
        """Names of `$defs` that no artifact of the OLD schema could reach.

        A `$def` qualifies only when EVERY reference chain from the root to it
        passes through a property absent from the old schema. Given
        `additionalProperties: false`, an old artifact cannot carry a property
        that did not exist, so a conditional requirement inside such a def can
        never invalidate one.

        Deliberately strict: reachable via even one pre-existing property (even
        an optional one, since an old artifact may well have populated it) and
        the def does not qualify.
        """

        def property_pointers(schema: dict) -> set:
            found = set()

            def walk(node, path):
                if isinstance(node, dict):
                    props = node.get("properties")
                    if isinstance(props, dict):
                        for name in props:
                            found.add("/" + "/".join([*path, "properties", name]))
                    for key, value in node.items():
                        walk(value, [*path, str(key)])
                elif isinstance(node, list):
                    for i, item in enumerate(node):
                        walk(item, [*path, str(i)])

            walk(schema, [])
            return found

        old_props = property_pointers(old)
        # (def_name -> set of bools: did this reference chain cross a new property?)
        arrivals: dict[str, set] = {}

        def walk(node, path, crossed_new, seen):
            if isinstance(node, dict):
                ref = node.get("$ref")
                if isinstance(ref, str) and ref.startswith("#/$defs/"):
                    name = ref[len("#/$defs/") :]
                    arrivals.setdefault(name, set()).add(crossed_new)
                    if name not in seen:
                        target = (current.get("$defs") or {}).get(name)
                        if isinstance(target, dict):
                            walk(target, ["$defs", name], crossed_new, seen | {name})
                for key, value in node.items():
                    if key == "$defs":
                        continue  # defs are visited through their refs only
                    if key == "properties" and isinstance(value, dict):
                        for name, sub in value.items():
                            sub_path = [*path, "properties", name]
                            ptr = "/" + "/".join(sub_path)
                            is_new = crossed_new or ptr not in old_props
                            walk(sub, sub_path, is_new, seen)
                        continue
                    walk(value, [*path, str(key)], crossed_new, seen)
            elif isinstance(node, list):
                for i, item in enumerate(node):
                    walk(item, [*path, str(i)], crossed_new, seen)

        walk(current, [], False, frozenset())
        old_defs = set((old.get("$defs") or {}).keys())
        return {
            name
            for name, flags in arrivals.items()
            if name not in old_defs and flags and all(flags)
        }

    @staticmethod
    def _collect_required(node: dict) -> set:
        """Collect required field names."""
        if "required" in node and isinstance(node["required"], list):
            return set(node["required"])
        return set()

    @pytest.mark.skipif(
        os.getenv("CONTRACTS_ALLOW_BREAKING") == "1",
        reason="Skipped when CONTRACTS_ALLOW_BREAKING=1",
    )
    def test_no_breaking_changes_vs_previous_tag(self):
        """Detect breaking schema changes: property removal, enum shrinkage, new required fields.

        Breaking changes (require MAJOR version bump):
        - Removing a property from a 'properties' object
        - Removing a value from an 'enum' array
        - Adding a new field to 'required'

        Allowed (MINOR/PATCH):
        - Adding properties
        - Adding enum values
        - Removing from required
        - Documentation changes

        If this fails: you have a breaking change. Bump VERSION to the next MAJOR
        and tag accordingly.
        """
        latest_tag = self._get_latest_tag()
        if not latest_tag:
            pytest.skip("No prior git tag found")

        breaking_changes = []

        for schema_file in sorted(SCHEMA_DIR.glob("*.schema.json")):
            # Fetch schema from the previous tag. Try the current (versioned) path first;
            # fall back to the pre-v1 unversioned path so the one-time schemas/ -> schemas/v1/
            # move doesn't make every schema look "new" and silently skip the gate.
            candidate_paths = [
                schema_file.relative_to(REPO_ROOT),
                Path("schemas") / schema_file.name,
            ]
            old_schema = None
            for candidate in candidate_paths:
                try:
                    result = subprocess.run(
                        ["git", "show", f"{latest_tag}:{candidate}"],
                        cwd=REPO_ROOT,
                        capture_output=True,
                        text=True,
                        check=True,
                    )
                    old_schema = json.loads(result.stdout)
                    break
                except subprocess.CalledProcessError:
                    continue
            if old_schema is None:
                # Schema didn't exist in previous tag under any known path — not a breaking change
                continue

            # Load current schema
            current_schema = json.loads(schema_file.read_text(encoding="utf-8"))

            # Walk both and compare
            old_nodes = {path: node for path, node in self._walk_schema(old_schema, [])}
            current_nodes = {path: node for path, node in self._walk_schema(current_schema, [])}

            for path, old_node in old_nodes.items():
                current_node = current_nodes.get(path)
                if not current_node:
                    continue

                # Check: removed properties
                old_props = self._collect_properties(old_node)
                new_props = self._collect_properties(current_node)
                removed = old_props - new_props
                if removed:
                    breaking_changes.append(
                        f"{schema_file.name}{path}: removed properties: {removed}"
                    )

                # Check: removed enum values
                old_enum = self._collect_enum_values(old_node)
                new_enum = self._collect_enum_values(current_node)
                if old_enum and new_enum:
                    removed_enum = old_enum - new_enum
                    if removed_enum:
                        breaking_changes.append(
                            f"{schema_file.name}{path}: removed enum values: {removed_enum}"
                        )

                # Check: new required fields
                old_required = self._collect_required(old_node)
                new_required = self._collect_required(current_node)
                new_req = new_required - old_required
                if new_req:
                    breaking_changes.append(
                        f"{schema_file.name}{path}: new required fields: {new_req}"
                    )

            # Check: newly introduced conditional requirements (if/then, allOf, oneOf,
            # dependentRequired). Node-by-node comparison above only sees paths present
            # in BOTH versions, so a brand-new conditional rule slips past it — yet a
            # conditional `required` rejects artifacts just as hard as a root one.
            old_conds = self._collect_conditional_required(old_schema)
            new_conds = self._collect_conditional_required(current_schema)
            # A conditional inside a $def that no OLD artifact could reach cannot
            # invalidate one. Without this, adding any new optional sub-object
            # with an internal if/then reads as a MAJOR break.
            unreachable = self._defs_reachable_only_via_new_properties(current_schema, old_schema)
            for pointer, fields in sorted(new_conds - old_conds):
                if any(pointer.startswith(f"/$defs/{name}/") for name in unreachable):
                    continue
                if self._anyof_satisfied_by_old_required(current_schema, old_schema, pointer):
                    continue
                breaking_changes.append(
                    f"{schema_file.name}{pointer}: new conditional requirement: {fields} "
                    "(artifacts not satisfying it become invalid)"
                )

        if breaking_changes:
            msg = "Breaking schema changes detected — requires MAJOR version bump and new tag:\n"
            for change in breaking_changes:
                msg += f"  - {change}\n"
            pytest.fail(msg)


class TestConditionalReachability:
    """The narrowing in `_defs_reachable_only_via_new_properties` must exempt
    ONLY conditionals no old artifact could reach. These tests exist so the
    exemption cannot quietly grow into "conditionals are fine".
    """

    H = TestBreakingChangeDetection

    OLD: ClassVar[dict] = {
        "type": "object",
        "properties": {"kept": {"$ref": "#/$defs/kept"}},
        "$defs": {"kept": {"type": "object", "properties": {"a": {"type": "string"}}}},
    }

    def test_new_def_behind_a_new_property_is_exempt(self):
        """The 5a case: new optional property -> new def -> internal if/then."""
        current = {
            "type": "object",
            "properties": {
                "kept": {"$ref": "#/$defs/kept"},
                "fresh": {"type": "array", "items": {"$ref": "#/$defs/fresh"}},
            },
            "$defs": {
                "kept": self.OLD["$defs"]["kept"],
                "fresh": {
                    "type": "object",
                    "allOf": [{"if": {}, "then": {"required": ["x"]}}],
                },
            },
        }
        assert "fresh" in self.H._defs_reachable_only_via_new_properties(current, self.OLD)

    def test_new_def_swapped_in_behind_a_PRE_EXISTING_property_is_not_exempt(self):
        """The unsound case: an existing property's $ref now points at a new def.

        Old artifacts already carry `kept`, so they are immediately subject to
        the new def's conditional. No new property stands between them and it.
        """
        current = {
            "type": "object",
            "properties": {"kept": {"$ref": "#/$defs/newkept"}},
            "$defs": {
                "kept": self.OLD["$defs"]["kept"],
                "newkept": {
                    "type": "object",
                    "properties": {"a": {"type": "string"}},
                    "allOf": [{"if": {}, "then": {"required": ["a"]}}],
                },
            },
        }
        assert "newkept" not in self.H._defs_reachable_only_via_new_properties(current, self.OLD)

    def test_new_def_behind_a_new_property_of_an_existing_def_is_exempt(self):
        """Chains may START at an old property: what matters is crossing a new one.

        `kept` is pre-existing, but the only route to `sneaky` is the NEW
        property `b`, and an old artifact cannot carry `b` under
        additionalProperties: false.
        """
        current = {
            "type": "object",
            "properties": {"kept": {"$ref": "#/$defs/kept"}},
            "$defs": {
                "kept": {
                    "type": "object",
                    "properties": {"a": {"type": "string"}, "b": {"$ref": "#/$defs/sneaky"}},
                },
                "sneaky": {"type": "object", "allOf": [{"if": {}, "then": {"required": ["x"]}}]},
            },
        }
        assert "sneaky" in self.H._defs_reachable_only_via_new_properties(current, self.OLD)

    def test_conditional_added_to_an_existing_def_is_never_exempt(self):
        """The case the gate exists for: tightening a def old artifacts use."""
        current = {
            "type": "object",
            "properties": {"kept": {"$ref": "#/$defs/kept"}},
            "$defs": {
                "kept": {
                    "type": "object",
                    "properties": {"a": {"type": "string"}},
                    "allOf": [{"if": {}, "then": {"required": ["a"]}}],
                }
            },
        }
        assert not self.H._defs_reachable_only_via_new_properties(current, self.OLD)
        conds = self.H._collect_conditional_required(current)
        assert conds - self.H._collect_conditional_required(self.OLD)

    def test_def_reachable_by_both_a_new_and_an_old_path_is_not_exempt(self):
        """All chains must be new; one pre-existing route is enough to disqualify."""
        current = {
            "type": "object",
            "properties": {
                "kept": {"$ref": "#/$defs/shared"},
                "fresh": {"$ref": "#/$defs/shared"},
            },
            "$defs": {
                "kept": self.OLD["$defs"]["kept"],
                "shared": {"type": "object", "allOf": [{"if": {}, "then": {"required": ["x"]}}]},
            },
        }
        assert "shared" not in self.H._defs_reachable_only_via_new_properties(current, self.OLD)


class TestAnyOfAlternatives:
    """The anyOf narrowing must exempt only alternatives an old artifact already meets."""

    H = TestBreakingChangeDetection
    OLD: ClassVar[dict] = {"$defs": {"t": {"type": "object", "required": ["a", "b", "c"]}}}

    def _new(self, branches, key="anyOf"):
        return {"$defs": {"t": {"type": "object", "required": ["a"], key: branches}}}

    def test_new_alternative_to_old_requirements_is_not_breaking(self):
        new = self._new([{"required": ["x"]}, {"required": ["b", "c"]}])
        for i in (0, 1):
            assert self.H._anyof_satisfied_by_old_required(new, self.OLD, f"/$defs/t/anyOf/{i}")

    def test_alternatives_old_artifacts_do_not_meet_stay_breaking(self):
        new = self._new([{"required": ["x"]}, {"required": ["b", "y"]}])
        assert not self.H._anyof_satisfied_by_old_required(new, self.OLD, "/$defs/t/anyOf/0")

    def test_oneof_is_never_exempt(self):
        new = self._new([{"required": ["x"]}, {"required": ["b", "c"]}], key="oneOf")
        assert not self.H._anyof_satisfied_by_old_required(new, self.OLD, "/$defs/t/oneOf/0")

    def test_branches_with_more_than_required_are_not_exempt(self):
        new = self._new([{"required": ["x"], "properties": {}}, {"required": ["b"]}])
        assert not self.H._anyof_satisfied_by_old_required(new, self.OLD, "/$defs/t/anyOf/1")
