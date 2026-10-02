SELECT byte_size, reference
FROM artifact_evidence
WHERE digest = :digest;
