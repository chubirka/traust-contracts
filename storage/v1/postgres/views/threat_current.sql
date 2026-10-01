-- Current threats, with the owner of the subject they were modelled against.
--
-- One threat model per subject, and a re-modelled subject must not count
-- twice. Same rule report_current applies to restated reports: most
-- recently bound wins, binding_id breaking ties.
--
-- Resolved per SUBJECT, not per scope. An earlier cut of this view read a
-- fleet-wide register and resolved one current document for the whole
-- scope -- wrong grain, and fed from the dashboard's own output. The
-- estate has one model per subject; that is what this counts.
--
-- Ownership is LEFT JOINed: a threat model can exist for a subject the
-- corpus registry does not declare, and such a model is still real. It
-- simply has no denominator.
CREATE OR REPLACE VIEW traust_storage.threat_current AS
SELECT b.scope_id,
       t.threat_key,
       t.threat_id,
       t.model,
       t.subject_id,
       t.product,
       t.statement,
       t.surface,
       t.asset,
       t.impact,
       t.likelihood,
       t.status,
       t.controls,
       t.evidence,
       t.attack_refs,
       t.linddun,
       t.score,
       t.isolation_dimensions,
       t.isolation_boundaries,
       owner.ownership,
       owner.business_unit,
       owner.tree,
       owner.is_branch_audit,
       t.risk_rating,
       t.severity,
       t.likelihood_score,
       t.likelihood_level,
       t.impact_score,
       t.impact_level,
       t.impact_basis
FROM traust_storage.threat t
JOIN traust_storage.artifact_binding b
  ON b.binding_id = t.binding_id
LEFT JOIN traust_storage.ownership_current owner
  ON owner.subject_id = b.subject_id
WHERE b.artifact_name = 'threat-model'
  AND NOT EXISTS (
      SELECT 1
      FROM traust_storage.artifact_binding rival
      WHERE rival.artifact_name = 'threat-model'
        AND rival.scope_id = b.scope_id
        AND rival.subject_id = b.subject_id
        AND (rival.bound_at > b.bound_at
             OR (rival.bound_at = b.bound_at AND rival.binding_id > b.binding_id))
  );
