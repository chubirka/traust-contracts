"""Config resolution and load_context behavior."""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

import jsonschema
import pytest
import yaml

from traust_contracts.config import (
    MANIFEST,
    TRAUST_CONFIG_HOME_ENV,
    DeploymentConfigMissing,
    ObjectStoreConfig,
    StorageConfig,
    config_completeness_audit,
    config_path,
    deployment_config_dir,
    load_context,
    load_section,
    optional_config_path,
)

_TRAUST_FIXTURES = Path(__file__).resolve().parents[2] / "traust" / "tests" / "fixtures" / "config"


def _write_minimal_config(home: Path) -> None:
    shutil.copytree(_TRAUST_FIXTURES, home, dirs_exist_ok=True)


def test_manifest_covers_harness_context_sections():
    manifest_sections = {entry.section for entry in MANIFEST}
    required = {
        "feeds",
        "external_tools",
        "model_registry",
        "corpus",
        "safe_exec",
        "signing_pubkey",
        "locations",
        "budget_policy",
        "product_map",
        "rule_pack_allowlist",
        "internal_vocabulary",
        "hardening_risk_weights",
        "rpm_distgit_watch",
        "storage",
        "object_store",
    }
    assert manifest_sections == required


def test_deployment_config_dir_honors_env(tmp_path, monkeypatch):
    home = tmp_path / "cfg"
    home.mkdir()
    monkeypatch.setenv(TRAUST_CONFIG_HOME_ENV, str(home))
    assert deployment_config_dir() == home


def test_load_context_resolves_relative_locations(tmp_path):
    home = tmp_path / "cfg"
    ws = tmp_path / "workspace"
    ar = tmp_path / "analysis-results"
    ws.mkdir()
    ar.mkdir()
    _write_minimal_config(home)
    (home / "locations.yaml").write_text(
        yaml.safe_dump(
            {
                "workspace": "../workspace",
                "analysis_results": "../analysis-results",
            }
        ),
        encoding="utf-8",
    )
    ctx = load_context(config_home=home)
    assert ctx.locations is not None
    assert ctx.locations.workspace == str(ws.resolve())
    assert ctx.locations.analysis_results == str(ar.resolve())


def test_load_section_locations_empty_file_loads(tmp_path):
    home = tmp_path / "cfg"
    _write_minimal_config(home)
    (home / "locations.yaml").write_text("{}\n", encoding="utf-8")
    loc = load_section("locations.yaml", config_home=home)
    assert loc is not None
    assert loc.progress_tracker is None


def test_config_completeness_flags_empty_corpus(tmp_path):
    home = tmp_path / "cfg"
    _write_minimal_config(home)
    (home / "corpus-config.yaml").write_text("version: 1\ntrees: {}\n", encoding="utf-8")
    errors, _warnings = config_completeness_audit(config_home=home)
    assert any("trees is empty" in e for e in errors)
    assert load_context(config_home=home).corpus.trees == {}


def test_config_completeness_warns_on_example_vocabulary(tmp_path):
    home = tmp_path / "cfg"
    _write_minimal_config(home)
    _, warnings = config_completeness_audit(config_home=home)
    assert any("yourorg.invalid" in w for w in warnings)
    assert any("rule-pack-allowlist" in w for w in warnings)
    assert any("1970-01-01" in w for w in warnings)


def test_config_path_and_optional(tmp_path, monkeypatch):
    home = tmp_path / "cfg"
    _write_minimal_config(home)
    monkeypatch.setenv(TRAUST_CONFIG_HOME_ENV, str(home))
    assert config_path("feeds.yaml") == home / "feeds.yaml"
    assert optional_config_path("locations.yaml") is None
    (home / "locations.yaml").write_text("workspace: /x\n", encoding="utf-8")
    assert optional_config_path("locations.yaml") == home / "locations.yaml"


def test_load_section_locations_normalizes(tmp_path):
    home = tmp_path / "cfg"
    ws = tmp_path / "workspace"
    ws.mkdir()
    _write_minimal_config(home)
    (home / "locations.yaml").write_text(
        yaml.safe_dump({"workspace": "../workspace"}),
        encoding="utf-8",
    )
    loc = load_section("locations.yaml", config_home=home)
    assert loc.workspace == str(ws.resolve())


def test_config_path_fails_when_home_unset(monkeypatch):
    monkeypatch.setattr("traust_contracts.config.deployment_config_dir", lambda: None)
    with pytest.raises(DeploymentConfigMissing, match=r"feeds.yaml"):
        config_path("feeds.yaml")


@pytest.mark.parametrize(
    "dsn",
    [
        "postgresql://localhost/test",
        "postgres://user:private-password@localhost/test",
        "sqlite:///:memory:",
        "sqlite:////absolute/path/audit.db",
    ],
)
def test_storage_section_uses_canonical_loader(tmp_path: Path, dsn: str) -> None:
    path = tmp_path / "storage.yaml"
    path.write_text(yaml.safe_dump({"dsn": dsn}), encoding="utf-8")
    section = load_section("storage", config_home=tmp_path, required=True)
    assert isinstance(section, StorageConfig)
    assert section.dsn == dsn
    assert section.source_sha == hashlib.sha256(path.read_bytes()).hexdigest()[:12]
    assert load_section("storage.yaml", config_home=tmp_path) == section
    assert dsn not in repr(section)


def test_context_storage_is_optional(tmp_path: Path) -> None:
    _write_minimal_config(tmp_path)
    assert load_context(config_home=tmp_path).storage is None
    (tmp_path / "storage.yaml").write_text(
        yaml.safe_dump({"dsn": "sqlite:///:memory:"}), encoding="utf-8"
    )
    assert load_context(config_home=tmp_path).storage.dsn == "sqlite:///:memory:"


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"dsn": None},
        {"dsn": 4},
        {"dsn": ""},
        {"dsn": "mysql://localhost/test"},
        {"dsn": "postgresql://localhost/test", "test_dsn": "postgresql://localhost/other"},
    ],
)
def test_storage_config_rejects_invalid_values(tmp_path: Path, data: dict) -> None:
    (tmp_path / "storage.yaml").write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises(jsonschema.ValidationError):
        load_section("storage", config_home=tmp_path)


def test_storage_section_missing_required_vs_optional(tmp_path: Path) -> None:
    assert load_section("storage", config_home=tmp_path) is None
    with pytest.raises(DeploymentConfigMissing, match=r"storage.yaml"):
        load_section("storage", config_home=tmp_path, required=True)


# --- scope resolution -------------------------------------------------------
# scope_id is storage/v1's authorization partition, and PostgreSQL enforces it
# inside the view: a query with no scope returns nothing rather than erroring.
# So the failure mode of getting this wrong is a silently empty dashboard.

SCOPE_TREES = {
    "findings": {"ownership": "owned", "label": "a", "business_unit": "Platform Group"},
    "cloud-config": {"ownership": "owned", "label": "b", "business_unit": "Platform Group"},
    "other-bu": {"ownership": "external-bu", "label": "c", "business_unit": "Other Unit"},
    "probes": {"ownership": "harness-qa", "label": "d", "business_unit": "Platform Group"},
}


def _corpus(**scope):
    from traust_contracts.config import CorpusConfig

    payload = {"version": 1, "trees": SCOPE_TREES}
    if scope:
        payload["scope"] = scope
    return CorpusConfig(**payload)


def test_scope_defaults_to_one_scope_so_an_absent_stanza_changes_nothing() -> None:
    config = _corpus()
    assert config.scope.mode == "single"
    assert config.readable_scopes() == ["local"]
    assert {config.scope_for(tree) for tree in SCOPE_TREES} == {"local"}


def test_business_unit_mode_gives_trees_sharing_a_unit_the_same_scope() -> None:
    """The whole point of the partition: two trees, one unit, one boundary."""
    config = _corpus(mode="business_unit")
    assert config.scope_for("findings") == config.scope_for("cloud-config") == "platform-group"
    assert config.scope_for("other-bu") == "other-unit"


def test_readable_scopes_omits_harness_qa_trees() -> None:
    """harness-qa is registered-but-not-corpus, excluded from every lens.

    Listing it as readable would readmit through the scope list exactly what
    the resolver excludes by ownership.
    """
    config = _corpus(mode="business_unit")
    assert config.readable_scopes() == ["other-unit", "platform-group"]
    # Still resolvable for writes — the artifacts exist, they are just not corpus.
    assert config.scope_for("probes") == "platform-group"


def test_every_mode_partitions_without_gaps_or_overlaps() -> None:
    """Each corpus tree lands in exactly one readable scope, in every mode."""
    for mode in ("single", "business_unit", "tree"):
        config = _corpus(mode=mode)
        readable = set(config.readable_scopes())
        corpus_trees = [t for t, m in SCOPE_TREES.items() if m["ownership"] != "harness-qa"]
        assigned = [config.scope_for(tree) for tree in corpus_trees]
        assert all(scope in readable for scope in assigned), mode
        assert set(assigned) == readable, mode


def test_explicit_mode_names_the_tree_it_cannot_resolve() -> None:
    config = _corpus(mode="explicit")
    with pytest.raises(ValueError, match="declares no scope_id"):
        config.scope_for("findings")

    from traust_contracts.config import CorpusConfig

    trees = {name: dict(meta) for name, meta in SCOPE_TREES.items()}
    for name in trees:
        trees[name]["scope_id"] = f"custom-{name}"
    declared = CorpusConfig(version=1, trees=trees, scope={"mode": "explicit"})
    assert declared.scope_for("findings") == "custom-findings"


def test_unknown_tree_and_unknown_mode_are_rejected() -> None:
    from traust_contracts.config import CorpusConfig

    with pytest.raises(KeyError, match="neither as a tree nor as an engagement"):
        _corpus().scope_for("never-registered")
    with pytest.raises(ValueError, match=r"scope\.mode must be one of"):
        CorpusConfig(version=1, trees=SCOPE_TREES, scope={"mode": "per-user"})


def test_readable_scopes_raises_rather_than_returning_empty() -> None:
    """An empty scope list returns zero rows on PostgreSQL, which reads as
    'no findings' when it means 'misconfigured'. Fail loudly instead."""
    from traust_contracts.config import CorpusConfig

    only_qa = {"probes": SCOPE_TREES["probes"]}
    with pytest.raises(ValueError, match="resolves to no scopes"):
        CorpusConfig(version=1, trees=only_qa).readable_scopes()


def test_scope_slug_is_deterministic_and_collision_free_on_real_shapes() -> None:
    from traust_contracts.config import scope_slug

    assert scope_slug("Hybrid Platforms") == "hybrid-platforms"
    assert scope_slug("Hybrid Platforms (upstream community dependencies)") == (
        "hybrid-platforms-upstream-community-dependencies"
    )
    assert scope_slug("  Spaced  Out  ") == "spaced-out"
    # Distinct units must not collapse onto one authorization boundary.
    assert scope_slug("Platform Group") != scope_slug("Platform Group 2")


def test_a_registered_engagement_tree_resolves_like_any_other() -> None:
    """Engagements are tree-per-engagement: a one-time scan for another
    business unit lands in its own directory, and resolver.active_trees()
    merges it in. Looking only at `trees` dropped 53 repos and 399
    findings that carry a declared ownership of external-bu."""
    from traust_contracts.config import CorpusConfig

    config = CorpusConfig(
        version=1,
        trees=SCOPE_TREES,
        engagements={
            "sidequest": {
                "label": "sidequest",
                "ownership": "external-bu",
                # A unit no declared TREE has, so readable_scopes() can only
                # contain it if engagements are resolved.
                "business_unit": "Sidequest Unit",
                "tree": "sidequest-findings",
            }
        },
        scope={"mode": "business_unit"},
    )
    assert config.tree_meta("sidequest-findings").ownership == "external-bu"
    assert config.scope_for("sidequest-findings") == "sidequest-unit"
    # It must also be READABLE, or its artifacts ingest into a scope no
    # query ever asks for.
    assert "sidequest-unit" in config.readable_scopes()


def test_an_engagement_tree_is_still_excluded_from_the_owned_denominator() -> None:
    """external-bu is Lens 1 (work performed) only. Inclusion in storage is
    not inclusion in the risk numbers -- the ownership tag does that."""
    from traust_contracts.config import CorpusConfig

    config = CorpusConfig(
        version=1,
        trees=SCOPE_TREES,
        engagements={
            "sidequest": {
                "label": "s",
                "ownership": "external-bu",
                "business_unit": "Other Unit",
                "tree": "sidequest-findings",
            }
        },
    )
    assert config.tree_meta("sidequest-findings").ownership != "owned"


# --- object-store.yaml --------------------------------------------------------

_AWS = {"backend": "s3", "region": "us-east-1", "bucket": "traust-artifacts", "prefix": "prod/"}


@pytest.mark.parametrize(
    "data",
    [
        _AWS,
        {**_AWS, "encryption": {"mode": "sse-s3"}},
        {
            **_AWS,
            "encryption": {
                "mode": "sse-kms",
                "kms_key_id": "arn:aws:kms:us-east-1:111122223333:key/example",
            },
        },
        {"backend": "s3", "endpoint": "minio.local:9000", "bucket": "dev-artifacts", "tls": False},
        {**_AWS, "max_object_bytes": 1048576},
    ],
)
def test_object_store_section_loads(tmp_path: Path, data: dict) -> None:
    path = tmp_path / "object-store.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    section = load_section("object_store", config_home=tmp_path, required=True)
    assert isinstance(section, ObjectStoreConfig)
    assert section.bucket == data["bucket"]
    assert section.tls is data.get("tls", True)
    assert section.source_sha == hashlib.sha256(path.read_bytes()).hexdigest()[:12]


@pytest.mark.parametrize(
    ("data", "why"),
    [
        ({"backend": "s3", "bucket": "traust-artifacts"}, "AWS S3 needs a region"),
        ({**_AWS, "backend": "gcs"}, "only s3 is supported"),
        ({**_AWS, "bucket": "Not_A_Bucket"}, "bucket naming"),
        ({**_AWS, "prefix": "prod"}, "prefix ends in /"),
        ({**_AWS, "endpoint": "https://minio.local"}, "endpoint has no scheme"),
        ({**_AWS, "encryption": {"mode": "sse-kms"}}, "sse-kms needs a key"),
        ({**_AWS, "secret_access_key": "x"}, "credentials are never config"),
        ({**_AWS, "access_key_id": "x"}, "credentials are never config"),
    ],
)
def test_object_store_section_rejects(tmp_path: Path, data: dict, why: str) -> None:
    (tmp_path / "object-store.yaml").write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises(Exception):  # noqa: B017 - the loader's validation error, whatever its type
        load_section("object_store", config_home=tmp_path, required=True)


def test_context_object_store_is_optional(tmp_path: Path) -> None:
    _write_minimal_config(tmp_path)
    assert load_context(config_home=tmp_path).object_store is None
    (tmp_path / "object-store.yaml").write_text(yaml.safe_dump(_AWS), encoding="utf-8")
    assert load_context(config_home=tmp_path).object_store.bucket == "traust-artifacts"
