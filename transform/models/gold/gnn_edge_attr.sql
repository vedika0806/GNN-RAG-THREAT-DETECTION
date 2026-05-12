{{
    config(
        materialized='table',
        schema='GOLD',
        tags=['gold'],
        comment='Gold: 11-dim normalized edge features per unique IP pair. Includes split mask and attack label.'
    )
}}

-- Aggregates 27M flows into 2,183 unique directed edges.
-- Key fix over notebook: ALL count-based features are log-scaled to prevent
-- the 6-orders-of-magnitude scale difference between dense/sparse edges.

WITH flows AS (
    SELECT
        src_ip_zeek,
        dest_ip_zeek,
        duration,
        orig_bytes,
        resp_bytes,
        orig_pkts,
        resp_pkts,
        proto,
        service,
        conn_state,
        CASE WHEN final_target = 'Attack' THEN 1 ELSE 0 END AS is_attack
    FROM {{ ref('network_logs_clean') }}
),

edge_raw AS (
    SELECT
        src_ip_zeek,
        dest_ip_zeek,

        -- Structural: how many times did this pair communicate?
        LN(1 + COUNT(*))                                        AS edge_weight,

        -- Behavioral: average log-scaled traffic metrics
        AVG(LN(1 + duration))                                   AS avg_log_duration,
        AVG(LN(1 + orig_bytes))                                 AS avg_log_orig_bytes,
        AVG(LN(1 + resp_bytes))                                 AS avg_log_resp_bytes,

        -- Protocol intensity: log-scaled so dense/sparse edges are comparable
        LN(1 + SUM(CASE WHEN proto = 'tcp' THEN 1 ELSE 0 END)) AS log_total_tcp,
        LN(1 + SUM(CASE WHEN proto = 'udp' THEN 1 ELSE 0 END)) AS log_total_udp,

        -- Service intensity
        LN(1 + SUM(CASE WHEN service = 'http' THEN 1 ELSE 0 END)) AS log_total_http,
        LN(1 + SUM(CASE WHEN service = 'dns'  THEN 1 ELSE 0 END)) AS log_total_dns,

        -- Connection quality: ratio of clean closes vs SYN-only (scan signal)
        SUM(CASE WHEN conn_state = 'S0' THEN 1 ELSE 0 END)
            / NULLIF(COUNT(*), 0)::FLOAT                        AS conn_s0_ratio,

        -- Attack intensity: continuous signal richer than MAX binary label
        SUM(is_attack) / NULLIF(COUNT(*), 0)::FLOAT            AS attack_flow_ratio,

        -- Binary edge label: 1 if ANY flow on this edge was an attack
        MAX(is_attack)                                          AS is_attack_edge,

        COUNT(*)                                                AS _flow_count

    FROM flows
    GROUP BY src_ip_zeek, dest_ip_zeek
),

with_node_ids AS (
    SELECT
        s.node_id   AS source_idx,
        d.node_id   AS target_idx,
        e.*
    FROM edge_raw e
    JOIN {{ ref('node_mapping') }} s ON e.src_ip_zeek = s.ip
    JOIN {{ ref('node_mapping') }} d ON e.dest_ip_zeek = d.ip
),

with_split AS (
    SELECT
        *,
        -- Deterministic train/val/test split by edge identity hash.
        -- No shuffling needed — stable across pipeline re-runs.
        -- Distribution: 0-6 = train (70%), 7-8 = val (20%), 9 = test (10%)
        -- We stratify by is_attack_edge by using two separate hash spaces.
        CASE
            WHEN is_attack_edge = 1 THEN
                CASE MOD(HASH(src_ip_zeek || '|' || dest_ip_zeek || '|attack'), 10)
                    WHEN 9 THEN 'test'
                    WHEN 8 THEN 'val'
                    WHEN 7 THEN 'val'
                    ELSE 'train'
                END
            ELSE
                CASE MOD(HASH(src_ip_zeek || '|' || dest_ip_zeek || '|normal'), 10)
                    WHEN 9 THEN 'test'
                    WHEN 8 THEN 'val'
                    WHEN 7 THEN 'val'
                    ELSE 'train'
                END
        END AS split
    FROM with_node_ids
)

SELECT
    -- Graph topology
    source_idx,
    target_idx,
    src_ip_zeek,
    dest_ip_zeek,

    -- Edge features (11-dim) — all on comparable log-scales for GNN convergence
    edge_weight,
    avg_log_duration,
    avg_log_orig_bytes,
    avg_log_resp_bytes,
    log_total_tcp,
    log_total_udp,
    log_total_http,
    log_total_dns,
    conn_s0_ratio,
    attack_flow_ratio,

    -- Labels and split
    is_attack_edge,
    split,

    -- Diagnostic
    _flow_count

FROM with_split
ORDER BY source_idx, target_idx
