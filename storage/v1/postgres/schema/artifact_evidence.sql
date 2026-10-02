CREATE TABLE IF NOT EXISTS traust_storage.artifact_evidence (
    digest TEXT NOT NULL,
    byte_size BIGINT NOT NULL CHECK (byte_size >= 0),
    first_ingested_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (digest)
);
