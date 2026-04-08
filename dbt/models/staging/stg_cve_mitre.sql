-- Staging: light cleaning on the raw ingested table
SELECT
    cve_id,
    trim(lower(matched_mitre_id))        AS mitre_tactic_id,
    toInt32(year)                         AS cve_year,
    toFloat32(severity_score)             AS severity_score,
    trim(description)                     AS description,
    now()                                 AS _loaded_at
FROM {{ source('raw', 'cve_mitre_master') }}
WHERE cve_id IS NOT NULL
  AND matched_mitre_id IS NOT NULL
  AND severity_score > 0