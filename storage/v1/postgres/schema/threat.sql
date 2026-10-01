-- Per-threat projection of the threat register.
--
-- Threat MODELS are prose Markdown and cannot be projected; the register is
-- their structured restatement, and this is one row per threat in it. The
-- register blob stays authoritative -- this is an index over it, the same
-- relationship report_finding has to report.findings.
--
-- `threat_key` is the identity, not `threat_id`: every model numbers its
-- threats from T1, so threat_id alone collides across every model.
CREATE TABLE IF NOT EXISTS traust_storage.threat (
    binding_id TEXT NOT NULL,
    artifact_digest TEXT NOT NULL,
    threat_key TEXT NOT NULL,
    threat_id TEXT NOT NULL,
    model TEXT NOT NULL,
    subject_id TEXT,
    product TEXT,
    statement TEXT,
    surface TEXT,
    asset TEXT,
    -- LEGACY labels, present only on a threat not yet re-rated with the
    -- OWASP Risk Rating Methodology (threat-model schema: impact/likelihood).
    impact TEXT,
    likelihood TEXT,
    -- OWASP Risk Rating Methodology rating (schema `risk_rating`): the whole
    -- block, factors and reasons included, and its derived values as typed
    -- columns so a view can filter and order by them. All NULL on a threat
    -- not yet re-rated. Severity is one of critical, high, medium, low, note.
    risk_rating JSONB,
    severity TEXT,
    likelihood_score DOUBLE PRECISION,
    likelihood_level TEXT,
    impact_score DOUBLE PRECISION,
    impact_level TEXT,
    impact_basis TEXT,
    -- Four states, and partially_mitigated is the largest in practice.
    -- Folding it into mitigated is the single biggest way to overstate
    -- threat coverage, so it stays its own value all the way to the view.
    status TEXT,
    controls TEXT,
    actors JSONB,
    -- Empty means modelled but NOT evidenced, which is a different claim
    -- from unmitigated. Kept so a view can tell the two apart.
    evidence JSONB,
    linddun INTEGER,
    -- LEGACY ordering for a threat not yet re-rated: impact weight x
    -- likelihood weight over the legacy labels. Never a calibrated risk value
    -- and never comparable to CVSS; NULL on an OWASP-rated threat, which
    -- orders by severity instead.
    score INTEGER,
    -- Column 11 of the threats table, default since harness 0.82.0.
    -- This is what an ATT&CK coverage rollup reads; omitting it drops
    -- every MITRE mapping the estate has recorded.
    attack_refs JSONB,
    isolation_dimensions JSONB,
    isolation_boundaries JSONB,
    PRIMARY KEY (binding_id, threat_key),
    FOREIGN KEY (binding_id, artifact_digest)
        REFERENCES traust_storage.artifact_binding(binding_id, artifact_digest)
);

CREATE INDEX IF NOT EXISTS idx_threat_subject ON traust_storage.threat (subject_id);
CREATE INDEX IF NOT EXISTS idx_threat_rank ON traust_storage.threat (status, score);
CREATE INDEX IF NOT EXISTS idx_threat_severity ON traust_storage.threat (status, severity);
