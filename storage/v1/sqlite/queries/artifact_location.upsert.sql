INSERT INTO artifact_location (
    binding_id,
    reference,
    registered_at
)
VALUES (
    :binding_id,
    :reference,
    :registered_at
)
ON CONFLICT (binding_id, reference) DO NOTHING;
