-- Final GNN-ready edge table with 80/20 transductive mask
SELECT
    *,
    CASE
        WHEN (ROW_NUMBER() OVER (ORDER BY source_idx, target_idx)) % 5 = 0
        THEN 'test'
        ELSE 'train'
    END AS split_mask
FROM {{ ref('mart_super_edges') }}