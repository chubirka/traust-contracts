INSERT INTO traust_storage.artifact_location (
    binding_id,
    reference,
    registered_at
)
VALUES (
    %(binding_id)s,
    %(reference)s,
    %(registered_at)s
)
ON CONFLICT (binding_id, reference) DO NOTHING;
