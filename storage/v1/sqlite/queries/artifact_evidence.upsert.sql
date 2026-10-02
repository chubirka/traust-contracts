INSERT INTO artifact_evidence (
    digest,
    byte_size,
    first_ingested_at
)
VALUES (
    :digest,
    :byte_size,
    :first_ingested_at
)
ON CONFLICT (digest) DO NOTHING;
