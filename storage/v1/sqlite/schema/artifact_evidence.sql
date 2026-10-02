CREATE TABLE IF NOT EXISTS artifact_evidence (
    digest TEXT NOT NULL,
    byte_size INTEGER NOT NULL CHECK (byte_size >= 0),
    first_ingested_at TEXT NOT NULL,
    PRIMARY KEY (digest)
);
