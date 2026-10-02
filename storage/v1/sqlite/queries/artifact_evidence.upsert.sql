INSERT INTO artifact_evidence (
    digest,
    byte_size,
    first_ingested_at,
    reference
)
VALUES (
    :digest,
    :byte_size,
    :first_ingested_at,
    :reference
)
ON CONFLICT (digest) DO NOTHING;
