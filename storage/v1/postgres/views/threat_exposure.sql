-- Threat exposure: every modelled threat classified once, aggregated.
--
-- The census equivalent for the threat lens. `status` is carried through
-- UNCOLLAPSED -- partially_mitigated is the largest bucket in practice
-- (the largest bucket by far), so folding it into mitigated is the single
-- biggest way to overstate threat coverage.
--
-- `severity` is the OWASP Risk Rating Methodology severity, NULL for threats
-- whose model has not been re-rated; those still group by their legacy
-- impact and likelihood labels, which are NULL on a rated threat. The two
-- never blend: a row is either rated or legacy.
--
-- `evidenced` separates a threat backed by a finding or validation from one
-- that is only modelled. "Unmitigated" and "unevidenced" are different
-- claims and a rollup that blends them cannot be acted on.
CREATE OR REPLACE VIEW traust_storage.threat_exposure AS
SELECT scope_id,
       tree,
       ownership,
       business_unit,
       product,
       impact,
       likelihood,
       status,
       CASE WHEN evidence IS NULL OR jsonb_array_length(evidence) = 0 THEN 0 ELSE 1 END AS evidenced,
       linddun,
       COUNT(*) AS threats,
       COUNT(DISTINCT subject_id) AS subjects,
       MAX(score) AS top_score,
       severity
FROM traust_storage.threat_current
GROUP BY scope_id, tree, ownership, business_unit, product, severity, impact,
         likelihood, status,
         CASE WHEN evidence IS NULL OR jsonb_array_length(evidence) = 0 THEN 0 ELSE 1 END,
         linddun;
