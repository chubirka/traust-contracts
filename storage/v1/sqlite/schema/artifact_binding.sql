CREATE TABLE IF NOT EXISTS artifact_binding (
    binding_id TEXT NOT NULL,
    artifact_digest TEXT NOT NULL REFERENCES artifact_evidence(digest),
    artifact_name TEXT NOT NULL,
    artifact_role TEXT,
    scope_id TEXT NOT NULL,
    subject_id TEXT,
    run_id TEXT,
    layer_id TEXT,
    supersedes_binding_id TEXT,
    bound_at TEXT NOT NULL,
    PRIMARY KEY (binding_id),
    UNIQUE (binding_id, artifact_digest)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_artifact_binding_successor
    ON artifact_binding (supersedes_binding_id)
    WHERE supersedes_binding_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_artifact_binding_context
    ON artifact_binding (scope_id, subject_id, run_id, artifact_name, artifact_role);

CREATE INDEX IF NOT EXISTS idx_artifact_binding_layer
    ON artifact_binding (scope_id, layer_id)
    WHERE layer_id IS NOT NULL;
