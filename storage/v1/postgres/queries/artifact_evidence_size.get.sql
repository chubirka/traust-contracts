SELECT byte_size
FROM traust_storage.artifact_evidence
WHERE digest = %(digest)s;
