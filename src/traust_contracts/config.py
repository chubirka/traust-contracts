"""Config contract + canonical loader for the AI security harness.

Contracts is the agreed parent, so it owns the *universals* of configuration:
what config files exist, their shapes (``config/v1/*.schema.json``), where they
live (``$TRAUST_CONFIG_HOME``), and the one way to load them into typed objects.

Ownership boundary:
    * contracts (here)  — the knowledge + mechanism: manifest, schemas, types,
      resolution rules, and :func:`load_context`. No estate data.
    * app (harness)     — the config *source*: templates, shipped defaults, and
      ``install_traust`` seeding. Not universal, so it stays there.
    * traust-engine    — a *consumer*: declares the subset it needs and receives
      a :class:`HarnessContext`; never resolves config itself.

Any CLI (engine or app) that needs config calls :func:`load_context` — one
implementation, so no two callers can disagree about what "the config" is.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Literal

import jsonschema
import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from traust_contracts.paths import config_schema_path

# --- resolution universals ----------------------------------------------------

#: Environment variable naming the one config root every consumer reads from.
TRAUST_CONFIG_HOME_ENV = "TRAUST_CONFIG_HOME"
#: Documented default, created by ``scripts/install_traust`` for adopters.
TRAUST_CONFIG_HOME_DEFAULT = Path.home() / ".traust" / "config"


class DeploymentConfigMissing(FileNotFoundError):
    """A required config file (or the config home itself) could not be resolved.

    Raised instead of silently falling back to a template or an empty default:
    a harness that runs on placeholder data reports numbers about nobody's
    estate and calls them real.
    """


def deployment_config_dir() -> Path | None:
    """The one config home, or ``None`` when there is none.

    ``$TRAUST_CONFIG_HOME`` when set; else the documented default
    ``~/.traust/config`` if it exists. One variable, one answer — no workspace
    scanning, no marker files, no second root in any code tree.
    """
    val = os.environ.get(TRAUST_CONFIG_HOME_ENV)
    if val:
        return Path(val).expanduser()
    if TRAUST_CONFIG_HOME_DEFAULT.is_dir():
        return TRAUST_CONFIG_HOME_DEFAULT
    return None


# --- completeness audit (doctor / CI) -----------------------------------------
# Install seeds real files with empty or default values. The loader parses any
# schema-valid file; completeness checks report what the operator still needs.

_CORE_LOCATION_FIELDS = (
    "workspace",
    "analysis_results",
    "progress_tracker",
)
_EXAMPLE_VOCABULARY_TOKEN = "yourorg.invalid"
_BUDGET_PLACEHOLDER_APPROVED = "1970-01-01"


def config_completeness_audit(
    *,
    config_home: Path | None = None,
) -> tuple[list[str], list[str]]:
    """Return ``(errors, warnings)`` for an installed config home.

    Errors block a production-ready deployment. Warnings flag optional files
    and fields the operator may still want to configure — ``install_traust
    --doctor`` prints both.
    """
    errors: list[str] = []
    warnings: list[str] = []
    try:
        ctx = load_context(config_home=config_home)
    except DeploymentConfigMissing as exc:
        return [str(exc)], warnings

    if not ctx.corpus.trees:
        errors.append(
            "corpus-config.yaml: trees is empty — register your analysis-results trees "
            "(see /corpus-intake or config/corpus-config.example.yaml)"
        )

    if ctx.locations is None:
        warnings.append("locations.yaml: absent — set runtime paths for features that need them")
    else:
        for field in _CORE_LOCATION_FIELDS:
            if not getattr(ctx.locations, field, None):
                warnings.append(f"locations.yaml: {field} unset")

    if ctx.product_map is None:
        warnings.append(
            "product-definitions-map.yaml: absent — add reviewed package→product "
            "mappings for /assign-findings-owners"
        )
    else:
        mappings = ctx.product_map.mappings or {}
        if not mappings.get("packages") and not mappings.get("repos"):
            warnings.append(
                "product-definitions-map.yaml: no mappings yet — run "
                "python3 -m traust.cli registry products --all"
            )
        elif _product_map_looks_like_example(mappings):
            warnings.append(
                "product-definitions-map.yaml: still contains example- placeholder "
                "mappings — replace with your reviewed package→product pairs"
            )

    if ctx.internal_vocabulary is None:
        warnings.append(
            "internal-vocabulary.yaml: absent — copy the example and replace "
            "patterns before running scan_internal_refs"
        )
    elif _vocabulary_looks_like_example(ctx.internal_vocabulary):
        warnings.append(
            "internal-vocabulary.yaml: still contains example yourorg.invalid "
            "patterns — replace with your organization's vocabulary"
        )

    if ctx.rpm_distgit_watch is not None and not ctx.rpm_distgit_watch.active:
        warnings.append(
            "rpm-distgit-watch.yaml: active list is empty — the dist-git release "
            "feeder will not watch any repos"
        )

    if ctx.budget_policy is not None:
        policy = ctx.budget_policy.budget_policy or {}
        if str(policy.get("approved")) == _BUDGET_PLACEHOLDER_APPROVED:
            warnings.append(
                "budget-policy.yaml: approved date is still the placeholder "
                "(1970-01-01) — anchor bands to your cost baseline"
            )
        note = str((policy.get("monthly_budget") or {}).get("note", "")).lower()
        if "placeholder" in note:
            warnings.append(
                "budget-policy.yaml: monthly_budget is still the shipped placeholder "
                "band — set usd_* to your cost report and clear the placeholder note"
            )

    if ctx.rule_pack_allowlist is not None and _rule_packs_look_like_example(
        ctx.rule_pack_allowlist,
    ):
        warnings.append(
            "rule-pack-allowlist.yaml: review pack sources and calibration notes "
            "for your estate (shipped example references smith-xyz/argus-observe-rules)"
        )

    if ctx.signing_pubkey is None:
        warnings.append(
            "ledger-signing-key.pub: absent — ledger layers record unsigned; "
            "generate a cosign key pair (see config/ledger-signing-key.example.pub)"
        )

    return errors, warnings


def _vocabulary_looks_like_example(vocab: InternalVocabulary) -> bool:
    for rule in vocab.rules:
        if not isinstance(rule, dict):
            continue
        # Regex patterns escape dots; normalize before matching example tokens.
        pattern = str(rule.get("pattern", "")).lower().replace("\\", "")
        if "yourorg.invalid" in pattern:
            return True
    return False


def _rule_packs_look_like_example(allowlist: RulePackAllowlist) -> bool:
    for pack in (allowlist.packs or {}).values():
        if not isinstance(pack, dict):
            continue
        source = str(pack.get("source", ""))
        if "smith-xyz/argus-observe-rules" in source:
            return True
    return False


def _product_map_looks_like_example(mappings: dict) -> bool:
    for group in ("packages", "repos"):
        for key, val in (mappings.get(group) or {}).items():
            if "example-" in str(key) or "example-" in str(val):
                return True
    return False


# --- typed sections -----------------------------------------------------------
# Permissive by design: the authoritative shape check is the JSON schema applied
# at load time; these models give typed access to the top-level keys and keep
# everything else via pydantic's extra="allow".


class _Section(BaseModel):
    model_config = ConfigDict(extra="allow")

    #: sha256[:12] of the source file this section was parsed from, set by the
    #: loader. Provenance for stamps/ledger rows without the core touching a file.
    source_sha: str | None = None


class FeedsConfig(_Section):
    version: int
    sources: dict[str, Any]


class ExternalTools(_Section):
    tools: list[Any]


class ModelSpec(_Section):
    """One concrete model: its tier class and (optional) list prices."""

    tier: str
    batch_eligible: bool = False
    price_per_mtok_in: float | None = None
    price_per_mtok_out: float | None = None


class ProviderSpec(_Section):
    models: dict[str, ModelSpec]
    #: free-form: a structured block in some estates, a prose note in others.
    data_handling: Any = None


class RoleSpec(_Section):
    """A routing role: the tier floor and the approved models at/above it."""

    floor: str
    approved: list[str] = []
    candidates: list[str] = []


class ModelRegistry(_Section):
    version: Any
    #: tier class name -> metadata (ordering is by _TIER_ORDER in the consumer).
    tiers: dict[str, Any]
    providers: dict[str, ProviderSpec]
    roles: dict[str, RoleSpec]
    updated: Any = None
    escalation: dict[str, Any] | None = None

    def all_models(self) -> dict[str, ModelSpec]:
        """Every model across providers, keyed by id (ids are unique)."""
        return {mid: m for p in self.providers.values() for mid, m in p.models.items()}


#: Ownership tags a corpus tree/engagement may carry.
OWNERSHIP_TAGS = ("owned", "upstream", "external-bu", "harness-qa")


class TreeMeta(_Section):
    """Ownership metadata for one corpus tree."""

    ownership: str
    label: str
    business_unit: str
    # Only read under scope.mode 'explicit'; derived modes ignore it.
    scope_id: str | None = None

    @field_validator("ownership")
    @classmethod
    def _known_ownership(cls, v: str) -> str:
        if v not in OWNERSHIP_TAGS:
            raise ValueError(f"ownership must be one of {OWNERSHIP_TAGS}, got {v!r}")
        return v


class EngagementMeta(TreeMeta):
    """A registered engagement tree (activates when it appears on disk)."""

    tree: str


SCOPE_MODES = ("single", "business_unit", "tree", "explicit")


def scope_slug(value: str) -> str:
    """Deterministic scope id from free text. Lowercase, non-alphanumeric to '-'.

    Deliberately literal rather than clever: a business unit named
    "Hybrid Platforms (upstream community dependencies)" becomes a long id
    rather than an invented short one, because a scope id is an
    authorization boundary and guessing abbreviations is how two units
    quietly collide. A deployment that wants a short id uses
    ``mode: explicit`` and says so.
    """
    slug = "".join(character if character.isalnum() else "-" for character in value.lower())
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug.strip("-")


class ScopeConfig(_Section):
    """How corpus trees map onto storage scope ids.

    ``scope_id`` is storage/v1's authorization partition, and PostgreSQL
    enforces it *inside* the view — a query that supplies no scope returns
    nothing rather than erroring. Absent this stanza every tree resolves to
    one scope, which is the behaviour of a deployment that has never thought
    about partitioning.
    """

    mode: str = "single"
    id: str = "local"

    @field_validator("mode")
    @classmethod
    def _known_mode(cls, v: str) -> str:
        if v not in SCOPE_MODES:
            raise ValueError(f"scope.mode must be one of {SCOPE_MODES}, got {v!r}")
        return v


class CorpusConfig(_Section):
    version: int
    trees: dict[str, TreeMeta]
    engagements: dict[str, EngagementMeta] = {}
    overrides: dict[str, Any] = {}
    scope: ScopeConfig = ScopeConfig()

    def tree_meta(self, tree: str):
        """Ownership metadata for a tree, whether declared as a tree OR as a
        registered engagement.

        Engagements are tree-per-engagement: a one-time scan for another
        business unit lands in its own directory rather than the portfolio
        tree, and `resolver.active_trees()` merges them in once that
        directory exists. Looking only at `trees` silently drops them --
        measured 2026-09-19, that lost 53 repos and 399 findings that carry
        a declared ownership of `external-bu`.
        """
        if tree in self.trees:
            return self.trees[tree]
        for engagement in self.engagements.values():
            if getattr(engagement, "tree", None) == tree:
                return engagement
        return None

    def scope_for(self, tree: str) -> str:
        """The scope id to WRITE when ingesting artifacts from ``tree``."""
        meta = self.tree_meta(tree)
        if meta is None:
            raise KeyError(
                f"tree {tree!r} is registered neither as a tree nor as an "
                "engagement in corpus-config"
            )
        mode = self.scope.mode
        if mode == "single":
            return self.scope.id
        if mode == "business_unit":
            return scope_slug(meta.business_unit)
        if mode == "tree":
            return scope_slug(tree)
        declared = getattr(meta, "scope_id", None)
        if not declared:
            raise ValueError(
                f"scope.mode is 'explicit' but tree {tree!r} declares no scope_id; "
                "add scope_id to every tree or choose a derived mode"
            )
        return str(declared)

    def readable_scopes(self) -> list[str]:
        """Every scope a reader may query. Pass this to ``query_*``, never a literal.

        Resolved from the registry rather than written into each dashboard so
        that registering a new tree or business unit surfaces it everywhere at
        once. A hardcoded list fails silently instead: the number simply drops
        and nothing errors.

        Raises rather than returning ``[]``. PostgreSQL fails closed, so an
        empty scope list reads as "no findings" when it means "misconfigured".

        ``harness-qa`` trees are omitted, matching the corpus resolver: they
        are registered-but-not-corpus (probe and benchmark output), excluded
        from every metrics lens. Including them here would readmit through
        the scope list exactly what the resolver excludes by ownership.
        """
        names = list(self.trees) + [
            e.tree for e in self.engagements.values() if getattr(e, "tree", None)
        ]
        scopes = sorted(
            {
                self.scope_for(name)
                for name in names
                if (meta := self.tree_meta(name)) and meta.ownership != "harness-qa"
            }
        )
        if not scopes:
            raise ValueError(
                "corpus-config resolves to no scopes; a query with an empty "
                "scope list returns zero rows, which is indistinguishable "
                "from an empty corpus. Register at least one tree."
            )
        return scopes


class SafeExecProfiles(_Section):
    version: Any
    profiles: dict[str, Any]


class BudgetPolicy(_Section):
    budget_policy: dict[str, Any]


class ProductDefinitionsMap(_Section):
    mappings: dict[str, Any]


class RulePackAllowlist(_Section):
    packs: dict[str, Any]


class InternalVocabulary(_Section):
    rules: list[Any]


class HardeningRiskWeights(_Section):
    version: Any
    default: float
    weights: dict[str, Any]


class RpmDistgitWatch(_Section):
    active: list[Any]


class StorageConfig(_Section):
    """Caller-owned database connection URI from storage.yaml; no environment overrides."""

    dsn: str = Field(repr=False)


class ObjectStoreEncryption(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["bucket-default", "sse-s3", "sse-kms"]
    kms_key_id: str | None = None


class ObjectStoreConfig(_Section):
    """Where storage/v1 artifact bytes live (object-store.yaml).

    storage/v1 records only digests and byte sizes; the bytes are kept here
    under ``<prefix>sha256/<digest>``. Holds no credentials: those come from the
    environment or the workload's identity.
    """

    backend: Literal["s3"]
    bucket: str
    endpoint: str | None = None
    region: str | None = None
    prefix: str = ""
    tls: bool = True
    encryption: ObjectStoreEncryption | None = None
    max_object_bytes: int | None = None


class Locations(_Section):
    """Where the harness reads/writes runtime data. Estate config, not engine
    knowledge — every field is a local path or a location URI. Owned wholly by
    the traust config (``locations.yaml``); no environment overrides."""

    workspace: str | None = None
    analysis_results: str | None = None
    portfolio_graph: str | None = None
    progress_tracker: str | None = None
    rule_drafts: str | None = None
    feeds_cache: str | None = None
    gitleaks_config: str | None = None
    opengrep_rules: str | None = None
    product_definitions: str | None = None
    sarif_tool_uri: str | None = None


# --- the manifest: the single source of truth for "what config exists" --------


@dataclass(frozen=True)
class ConfigFile:
    """One config file's universal facts."""

    name: str  # filename in the config home
    section: str  # attribute name on HarnessContext
    required: bool
    kind: str  # "yaml" | "json" | "key"
    schema: str | None  # config schema basename, None for keys
    model: type[_Section] | None  # typed section model, None for keys


MANIFEST: tuple[ConfigFile, ...] = (
    # shipped defaults (required)
    ConfigFile("feeds.yaml", "feeds", True, "yaml", "feeds", FeedsConfig),
    ConfigFile(
        "external-tools.yaml", "external_tools", True, "yaml", "external-tools", ExternalTools
    ),
    ConfigFile(
        "model-registry.yaml", "model_registry", True, "yaml", "model-registry", ModelRegistry
    ),
    # deployment (required)
    ConfigFile("corpus-config.yaml", "corpus", True, "yaml", "corpus-config", CorpusConfig),
    ConfigFile(
        "safe-exec-profiles.yaml", "safe_exec", True, "yaml", "safe-exec-profiles", SafeExecProfiles
    ),
    # optional: absent key disables signature verification, not the ledger.
    ConfigFile("ledger-signing-key.pub", "signing_pubkey", False, "key", None, None),
    # optional (feature-gated → None when absent)
    ConfigFile("budget-policy.yaml", "budget_policy", False, "yaml", "budget-policy", BudgetPolicy),
    ConfigFile(
        "product-definitions-map.yaml",
        "product_map",
        False,
        "yaml",
        "product-definitions-map",
        ProductDefinitionsMap,
    ),
    ConfigFile(
        "rule-pack-allowlist.yaml",
        "rule_pack_allowlist",
        False,
        "yaml",
        "rule-pack-allowlist",
        RulePackAllowlist,
    ),
    ConfigFile(
        "internal-vocabulary.yaml",
        "internal_vocabulary",
        False,
        "yaml",
        "internal-vocabulary",
        InternalVocabulary,
    ),
    ConfigFile(
        "hardening-risk-weights.json",
        "hardening_risk_weights",
        False,
        "json",
        "hardening-risk-weights",
        HardeningRiskWeights,
    ),
    ConfigFile(
        "rpm-distgit-watch.yaml",
        "rpm_distgit_watch",
        False,
        "yaml",
        "rpm-distgit-watch",
        RpmDistgitWatch,
    ),
    ConfigFile("locations.yaml", "locations", False, "yaml", "locations", Locations),
    ConfigFile("storage.yaml", "storage", False, "yaml", "storage", StorageConfig),
    ConfigFile(
        "object-store.yaml", "object_store", False, "yaml", "object-store", ObjectStoreConfig
    ),
)


# --- the full context ---------------------------------------------------------


class HarnessContext(BaseModel):
    """Every resolved config the harness uses, loaded once at an entry point.

    Engine consumers take the subset they declare (see traust_engine); the app
    holds the whole thing. Built only by :func:`load_context`.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True, frozen=True)

    config_home: Path

    # shipped defaults (required)
    feeds: FeedsConfig
    external_tools: ExternalTools
    model_registry: ModelRegistry

    # deployment (required)
    corpus: CorpusConfig
    safe_exec: SafeExecProfiles

    # optional (None = feature off)
    #: Ledger signing public key. None disables signature *verification* (the
    #: ledger still records unsigned layers); operators enforce integrity by
    #: providing a key or via keyless/OIDC + LAAS_SIGNING_REQUIRED=1.
    signing_pubkey: Path | None = None
    locations: Locations | None = None
    storage: StorageConfig | None = None
    object_store: ObjectStoreConfig | None = None
    budget_policy: BudgetPolicy | None = None
    product_map: ProductDefinitionsMap | None = None
    rule_pack_allowlist: RulePackAllowlist | None = None
    internal_vocabulary: InternalVocabulary | None = None
    hardening_risk_weights: HardeningRiskWeights | None = None
    rpm_distgit_watch: RpmDistgitWatch | None = None


# --- the canonical loader -----------------------------------------------------


def _example_name(name: str) -> str:
    stem, dot, ext = name.rpartition(".")
    return f"{stem}.example.{ext}" if dot else f"{name}.example"


def _missing(home: Path, name: str, why: str) -> DeploymentConfigMissing:
    return DeploymentConfigMissing(
        f"required config file {name!r} {why} in {home}. Copy "
        f"config/{_example_name(name)} there as {name!r} and fill it in, or run "
        f"scripts/install_traust."
    )


_LOCATION_PATH_FIELDS = (
    "workspace",
    "analysis_results",
    "portfolio_graph",
    "progress_tracker",
    "rule_drafts",
    "feeds_cache",
    "gitleaks_config",
    "opengrep_rules",
)


def _resolve_location_path(home: Path, value: str | None) -> str | None:
    """Resolve a local path relative to the config home; leave URIs untouched."""
    if not value or "://" in value:
        return value
    p = Path(value)
    if p.is_absolute():
        return value
    return str((home / p).resolve())


def _normalize_locations(home: Path, section: Locations) -> Locations:
    """Make relative ``locations.yaml`` paths absolute against ``config_home``."""
    updates = {
        field: _resolve_location_path(home, getattr(section, field))
        for field in _LOCATION_PATH_FIELDS
        if getattr(section, field) is not None
    }
    return section.model_copy(update=updates) if updates else section


def _load_one(home: Path, entry: ConfigFile) -> Any | None:
    path = home / entry.name
    if not path.is_file():
        if entry.required:
            raise _missing(home, entry.name, "not found")
        return None

    if entry.kind == "key":
        return path

    raw = path.read_bytes()
    text = raw.decode("utf-8")
    data = json.loads(text) if entry.kind == "json" else yaml.safe_load(text)

    if entry.schema is not None:
        schema = json.loads(config_schema_path(entry.schema).read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator(schema).validate(data)

    if entry.model is None:
        return data
    section = entry.model.model_validate(data)
    section.source_sha = hashlib.sha256(raw).hexdigest()[:12]
    if entry.model is Locations:
        section = _normalize_locations(home, section)
    return section


def load_context(*, config_home: Path | None = None) -> HarnessContext:
    """Resolve the one config home and load every file into a HarnessContext.

    Required-and-absent raises :class:`DeploymentConfigMissing` naming the file
    and the fix; optional-and-absent becomes ``None``. Each file is validated
    against its ``config/v1`` schema. Use :func:`config_completeness_audit` to
    see what still needs operator input. Fail once, here — never deep in a module
    at an unpredictable moment.
    """
    home = Path(config_home) if config_home is not None else deployment_config_dir()
    if home is None:
        raise DeploymentConfigMissing(
            f"no config home: set ${TRAUST_CONFIG_HOME_ENV} or run scripts/install_traust "
            f"(default {TRAUST_CONFIG_HOME_DEFAULT})."
        )
    home = Path(home)

    values: dict[str, Any] = {"config_home": home}
    for entry in MANIFEST:
        values[entry.section] = _load_one(home, entry)
    return HarnessContext.model_validate(values)


# --- narrow single-file access ------------------------------------------------
# For feature-gated deep consumers: load ONE file without requiring the whole
# estate context (a narrow feature must not break because an unrelated required
# file is absent or malformed). Entry points should prefer load_context().

_BY_NAME = {e.name: e for e in MANIFEST}
_BY_SECTION = {e.section: e for e in MANIFEST}


def load_section(
    name: str, *, config_home: Path | None = None, required: bool | None = None
) -> Any | None:
    """Load one config file, schema-validated and typed, by filename or section.

    ``required`` overrides the manifest default — e.g. a consumer that degrades
    gracefully passes ``required=False`` to get ``None`` instead of an error when
    a manifest-required file is absent. Returns the typed section (or a ``Path``
    for key files), or ``None`` when optional-and-absent.
    """
    entry = _BY_NAME.get(name) or _BY_SECTION.get(name)
    if entry is None:
        raise KeyError(f"unknown config file {name!r}")
    if required is not None and required != entry.required:
        entry = replace(entry, required=required)
    home = Path(config_home) if config_home is not None else deployment_config_dir()
    if home is None:
        if entry.required:
            raise DeploymentConfigMissing(
                f"required config file {entry.name!r}: no config home — set "
                f"${TRAUST_CONFIG_HOME_ENV} or run scripts/install_traust."
            )
        return None
    return _load_one(Path(home), entry)


def config_path(name: str) -> Path:
    """Resolve a REQUIRED config file path from the one config home.

    Raises :class:`DeploymentConfigMissing` when the home is unset or the file
    is absent. For raw-path needs (keys); prefer :func:`load_section` for typed
    config or :func:`load_context` at entry points.
    """
    dep = deployment_config_dir()
    if dep is not None and (dep / name).is_file():
        return dep / name
    where = (
        str(dep)
        if dep is not None
        else f"<${TRAUST_CONFIG_HOME_ENV} unset and {TRAUST_CONFIG_HOME_DEFAULT} absent>"
    )
    raise DeploymentConfigMissing(
        f"required config file {name!r} not found in {where}. Copy "
        f"config/{_example_name(name)} there as {name!r} and fill it in, or run "
        f"scripts/install_traust."
    )


def optional_config_path(name: str) -> Path | None:
    """Resolve a feature-gated OPTIONAL config file path, or ``None`` when absent."""
    dep = deployment_config_dir()
    if dep is not None and (dep / name).is_file():
        return dep / name
    return None
