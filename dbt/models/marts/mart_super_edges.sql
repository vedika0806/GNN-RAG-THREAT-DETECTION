-- Aggregate 27M rows → 2,183 directed super-edges (mirrors your GNN prep)
SELECT
    s.node_id                        AS source_idx,
    d.node_id                        AS target_idx,
    COUNT(*)                         AS connection_count,
    AVG(e.log_duration)              AS mean_log_duration,
    STDDEV(e.log_duration)           AS std_log_duration,
    AVG(e.log_orig_bytes)            AS mean_log_orig_bytes,
    AVG(e.log_resp_bytes)            AS mean_log_resp_bytes,
    SUM(e.proto_tcp)                 AS tcp_count,
    SUM(e.proto_udp)                 AS udp_count,
    SUM(e.proto_icmp)                AS icmp_count,
    MAX(e.label)                     AS label   -- Attack if ANY connection was attack
FROM {{ ref('int_network_clean') }} e
JOIN {{ ref('mart_node_mapping') }} s ON e.src_ip_zeek  = s.ip
JOIN {{ ref('mart_node_mapping') }} d ON e.dest_ip_zeek = d.ip
GROUP BY s.node_id, d.node_id