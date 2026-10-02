CREATE TABLE IF NOT EXISTS traust_storage.artifact_location (
    binding_id TEXT NOT NULL REFERENCES traust_storage.artifact_binding(binding_id),
    reference TEXT NOT NULL CHECK (reference <> ''),
    registered_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (binding_id, reference)
);
