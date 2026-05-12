{{
    config(
        materialized='table',
        schema='GOLD',
        tags=['gold'],
        comment='Gold: edge index pairs (source_idx, target_idx) for PyG edge_index tensor.'
    )
}}

-- Lightweight view of just the integer edge pairs.
-- Separated from gnn_edge_attr so the Airflow export task can pull them
-- independently if needed (e.g., for graph structure analysis without features).

SELECT
    source_idx,
    target_idx,
    src_ip_zeek,
    dest_ip_zeek,
    is_attack_edge,
    split
FROM {{ ref('gnn_edge_attr') }}
ORDER BY source_idx, target_idx
