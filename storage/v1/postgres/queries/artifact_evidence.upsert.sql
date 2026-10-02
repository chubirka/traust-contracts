INSERT INTO traust_storage.artifact_evidence (
    digest,
    byte_size,
    first_ingested_at,
    reference
)
VALUES (
    %(digest)s,
    %(byte_size)s,
    %(first_ingested_at)s,
    %(reference)s
)
ON CONFLICT (digest) DO NOTHING;
