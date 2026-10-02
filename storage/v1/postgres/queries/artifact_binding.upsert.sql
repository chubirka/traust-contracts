INSERT INTO traust_storage.artifact_binding (
    binding_id,
    artifact_digest,
    artifact_name,
    artifact_role,
    scope_id,
    subject_id,
    run_id,
    layer_id,
    supersedes_binding_id,
    bound_at
)
VALUES (
    %(binding_id)s,
    %(artifact_digest)s,
    %(artifact_name)s,
    %(artifact_role)s,
    %(scope_id)s,
    %(subject_id)s,
    %(run_id)s,
    %(layer_id)s,
    %(supersedes_binding_id)s,
    %(bound_at)s
)
ON CONFLICT (binding_id) DO NOTHING;
