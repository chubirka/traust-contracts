SELECT scope_id,
       tree,
       ownership,
       business_unit,
       product,
       impact,
       likelihood,
       status,
       evidenced,
       linddun,
       threats,
       subjects,
       top_score,
       severity
FROM threat_exposure
WHERE scope_id IN (SELECT value FROM json_each(:scope_ids))
ORDER BY scope_id, tree, product,
         CASE severity
             WHEN 'critical' THEN 0
             WHEN 'high' THEN 1
             WHEN 'medium' THEN 2
             WHEN 'low' THEN 3
             WHEN 'note' THEN 4
             ELSE 5
         END,
         impact, likelihood, status;
