-- Singular test: Attack edge ratio must stay within expected bounds.
-- Ratio outside [2%, 80%] suggests a labeling bug or data drift.

WITH stats AS (
    SELECT
        SUM(is_attack_edge)::FLOAT / COUNT(*)   AS attack_ratio
    FROM {{ ref('gnn_edge_attr') }}
)

SELECT attack_ratio
FROM stats
WHERE attack_ratio < 0.02 OR attack_ratio > 0.80
