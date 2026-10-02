SELECT artifact_digest,
       artifact_name,
       scope_id,
       subject_id,
       run_id,
       layer_id,
       supersedes_binding_id,
       bound_at,
       artifact_role
FROM traust_storage.artifact_binding
WHERE binding_id = %(binding_id)s;
