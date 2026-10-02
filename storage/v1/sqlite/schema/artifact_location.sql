CREATE TABLE IF NOT EXISTS artifact_location (
    binding_id TEXT NOT NULL REFERENCES artifact_binding(binding_id),
    reference TEXT NOT NULL CHECK (reference <> ''),
    registered_at TEXT NOT NULL,
    PRIMARY KEY (binding_id, reference)
);
