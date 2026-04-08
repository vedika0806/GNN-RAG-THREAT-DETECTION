-- Mart: aggregated threat intelligence index for GraphRAG consumption
SELECT
    mitre_tactic_id,
    tactic_label,
    cve_year,
    severity_band,
    count(*)                              AS cve_count,
    avg(severity_score)                   AS avg_severity,
    max(severity_score)                   AS max_severity,
    min(severity_score)                   AS min_severity
FROM {{ ref('int_cve_enriched') }}
GROUP BY
    mitre_tactic_id,
    tactic_label,
    cve_year,
    severity_band
ORDER BY avg_severity DESC