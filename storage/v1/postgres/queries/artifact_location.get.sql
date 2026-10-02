SELECT reference
FROM traust_storage.artifact_location
WHERE binding_id = %(binding_id)s
ORDER BY registered_at, reference;
