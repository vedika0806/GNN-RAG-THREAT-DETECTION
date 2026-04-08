-- Intermediate: enrich with tactic labels and severity bands
SELECT
    cve_id,
    mitre_tactic_id,
    cve_year,
    severity_score,
    description,
    CASE
        WHEN severity_score >= 9.0 THEN 'CRITICAL'
        WHEN severity_score >= 7.0 THEN 'HIGH'
        WHEN severity_score >= 4.0 THEN 'MEDIUM'
        ELSE 'LOW'
    END                                   AS severity_band,
    CASE
        WHEN mitre_tactic_id = 't1190' THEN 'Exploit Public-Facing Application'
        WHEN mitre_tactic_id = 't1048' THEN 'Exfiltration Over Alt Protocol'
        WHEN mitre_tactic_id = 't1110' THEN 'Brute Force'
        ELSE 'Other'
    END                                   AS tactic_label,
    _loaded_at
FROM {{ ref('stg_cve_mitre') }}