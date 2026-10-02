SELECT byte_size, reference
FROM traust_storage.artifact_evidence
WHERE digest = %(digest)s;
