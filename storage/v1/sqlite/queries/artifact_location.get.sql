SELECT reference
FROM artifact_location
WHERE binding_id = :binding_id
ORDER BY registered_at, reference;
