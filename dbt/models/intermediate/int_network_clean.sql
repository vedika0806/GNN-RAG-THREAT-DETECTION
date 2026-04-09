-- Log-scaling + Top-K One-Hot Encoding — exact replication of your EDA cell 88
SELECT
    src_ip_zeek,
    dest_ip_zeek,
    -- Log Transformation (mirrors your ln(1+x) approach)
    ln(1 + duration)             AS log_duration,
    ln(1 + orig_bytes)           AS log_orig_bytes,
    ln(1 + resp_bytes)           AS log_resp_bytes,
    ln(1 + orig_pkts)            AS log_orig_pkts,
    ln(1 + resp_pkts)            AS log_resp_pkts,
    -- Protocol One-Hot
    CASE WHEN proto = 'tcp'  THEN 1 ELSE 0 END AS proto_tcp,
    CASE WHEN proto = 'udp'  THEN 1 ELSE 0 END AS proto_udp,
    CASE WHEN proto = 'icmp' THEN 1 ELSE 0 END AS proto_icmp,
    -- Top-5 Service One-Hot
    CASE WHEN service = 'http'    THEN 1 ELSE 0 END AS srv_http,
    CASE WHEN service = 'dns'     THEN 1 ELSE 0 END AS srv_dns,
    CASE WHEN service = 'ssl'     THEN 1 ELSE 0 END AS srv_ssl,
    CASE WHEN service = 'ssh'     THEN 1 ELSE 0 END AS srv_ssh,
    CASE WHEN service = 'unknown' THEN 1 ELSE 0 END AS srv_unknown,
    -- Target
    CASE WHEN final_target = 'Attack' THEN 1 ELSE 0 END AS label,
    label_tactic,
    label_technique,
    final_target
FROM {{ ref('stg_network_logs') }}