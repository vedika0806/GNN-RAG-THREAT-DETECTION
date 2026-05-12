{{
    config(
        materialized='table',
        schema='GOLD',
        tags=['gold'],
        comment='Gold: 15-dim behavioral node features per IP. Replaces identity matrix from notebook.'
    )
}}

-- Per-IP behavioral aggregation across all flows.
-- This replaces torch.eye(1176) with semantically meaningful features.
-- Each feature captures a different aspect of the IP's role in the network.

WITH flows AS (
    SELECT
        src_ip_zeek,
        dest_ip_zeek,
        duration,
        duration_known,
        orig_bytes,
        bytes_known,
        resp_bytes,
        orig_pkts,
        resp_pkts,
        proto,
        service,
        conn_state,
        local_orig,
        local_resp,
        final_target
    FROM {{ ref('network_logs_clean') }}
),

-- Outgoing traffic profile (behavior as a source/client)
outgoing AS (
    SELECT
        src_ip_zeek AS ip,
        COUNT(*)                                                    AS total_flows_out,
        COUNT(DISTINCT dest_ip_zeek)                                AS out_degree,
        AVG(LN(1 + duration))                                       AS avg_log_duration_out,
        AVG(LN(1 + orig_bytes))                                     AS avg_log_orig_bytes_out,
        SUM(CASE WHEN final_target = 'Attack' THEN 1 ELSE 0 END)
            / NULLIF(COUNT(*), 0)::FLOAT                            AS attack_ratio_out,
        SUM(CASE WHEN proto = 'tcp' THEN 1 ELSE 0 END)
            / NULLIF(COUNT(*), 0)::FLOAT                            AS proto_tcp_ratio_out,
        SUM(CASE WHEN proto = 'udp' THEN 1 ELSE 0 END)
            / NULLIF(COUNT(*), 0)::FLOAT                            AS proto_udp_ratio_out,
        SUM(CASE WHEN service = 'http' THEN 1 ELSE 0 END)
            / NULLIF(COUNT(*), 0)::FLOAT                            AS srv_http_ratio_out,
        SUM(CASE WHEN service = 'dns' THEN 1 ELSE 0 END)
            / NULLIF(COUNT(*), 0)::FLOAT                            AS srv_dns_ratio_out,
        -- SF = successfully completed conn; high SF ratio → legitimate client
        -- S0 = SYN only (no response); high S0 ratio → scanner signature
        SUM(CASE WHEN conn_state = 'SF' THEN 1 ELSE 0 END)
            / NULLIF(COUNT(*), 0)::FLOAT                            AS conn_sf_ratio_out,
        SUM(CASE WHEN conn_state = 'S0' THEN 1 ELSE 0 END)
            / NULLIF(COUNT(*), 0)::FLOAT                            AS conn_s0_ratio_out
    FROM flows
    GROUP BY src_ip_zeek
),

-- Incoming traffic profile (behavior as a destination/server)
incoming AS (
    SELECT
        dest_ip_zeek AS ip,
        COUNT(*)                                                    AS total_flows_in,
        COUNT(DISTINCT src_ip_zeek)                                 AS in_degree,
        AVG(LN(1 + resp_bytes))                                     AS avg_log_resp_bytes_in,
        SUM(CASE WHEN final_target = 'Attack' THEN 1 ELSE 0 END)
            / NULLIF(COUNT(*), 0)::FLOAT                            AS attack_ratio_in
    FROM flows
    GROUP BY dest_ip_zeek
),

-- Join outgoing and incoming, then join with node_mapping for integer ID
node_raw AS (
    SELECT
        nm.node_id,
        nm.ip,
        nm.is_local,

        -- Outgoing features (NULL when IP never appears as source)
        COALESCE(o.total_flows_out, 0)          AS total_flows_out,
        COALESCE(o.out_degree, 0)               AS out_degree,
        COALESCE(o.avg_log_duration_out, 0)     AS avg_log_duration_out,
        COALESCE(o.avg_log_orig_bytes_out, 0)   AS avg_log_orig_bytes_out,
        COALESCE(o.attack_ratio_out, 0)         AS attack_ratio_out,
        COALESCE(o.proto_tcp_ratio_out, 0)      AS proto_tcp_ratio_out,
        COALESCE(o.proto_udp_ratio_out, 0)      AS proto_udp_ratio_out,
        COALESCE(o.srv_http_ratio_out, 0)       AS srv_http_ratio_out,
        COALESCE(o.srv_dns_ratio_out, 0)        AS srv_dns_ratio_out,
        COALESCE(o.conn_sf_ratio_out, 0)        AS conn_sf_ratio_out,
        COALESCE(o.conn_s0_ratio_out, 0)        AS conn_s0_ratio_out,

        -- Incoming features
        COALESCE(i.total_flows_in, 0)           AS total_flows_in,
        COALESCE(i.in_degree, 0)                AS in_degree,
        COALESCE(i.avg_log_resp_bytes_in, 0)    AS avg_log_resp_bytes_in,
        COALESCE(i.attack_ratio_in, 0)          AS attack_ratio_in

    FROM {{ ref('node_mapping') }} nm
    LEFT JOIN outgoing o ON nm.ip = o.ip
    LEFT JOIN incoming i ON nm.ip = i.ip
)

SELECT
    node_id,
    ip,

    -- Feature 1: degree features (log-scaled to handle hub-vs-leaf asymmetry)
    LN(1 + out_degree)              AS log_out_degree,
    LN(1 + in_degree)               AS log_in_degree,

    -- Feature 2: volume features
    LN(1 + total_flows_out)         AS log_flows_out,
    LN(1 + total_flows_in)          AS log_flows_in,

    -- Feature 3: behavioral byte/duration profile
    avg_log_duration_out,
    avg_log_orig_bytes_out,
    avg_log_resp_bytes_in,

    -- Feature 4: threat indicators
    attack_ratio_out,
    attack_ratio_in,

    -- Feature 5: protocol profile (ratios sum to ≤1.0, compatible with GNN)
    proto_tcp_ratio_out,
    proto_udp_ratio_out,

    -- Feature 6: service profile
    srv_http_ratio_out,
    srv_dns_ratio_out,

    -- Feature 7: connection quality (scan detection)
    conn_sf_ratio_out,

    -- Feature 8: topology context
    is_local::FLOAT                 AS is_local

    -- Total: 15 features per node (compact vs 1176-dim identity matrix)

FROM node_raw
ORDER BY node_id
