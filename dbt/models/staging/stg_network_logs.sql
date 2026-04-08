-- Mirrors your EDA notebook: remove Duplicates, resolve final_target
SELECT
    uid,
    src_ip_zeek,
    dest_ip_zeek,
    src_port_zeek,
    dest_port_zeek,
    proto,
    service,
    COALESCE(duration, 0)        AS duration,
    COALESCE(orig_bytes, 0)      AS orig_bytes,
    COALESCE(resp_bytes, 0)      AS resp_bytes,
    orig_pkts,
    resp_pkts,
    orig_ip_bytes,
    resp_ip_bytes,
    missed_bytes,
    conn_state,
    COALESCE(history, '-')       AS history,
    CASE
        WHEN vlan IS NULL OR vlan = 'unknown' OR vlan = 'NaN' THEN 'none'
        ELSE CAST(CAST(vlan AS FLOAT) AS INTEGER)::VARCHAR
    END                          AS vlan,
    label_tactic,
    label_technique,
    source_period,
    datetime,
    ts,
    CASE
        WHEN label_tactic != 'none' AND label_tactic IS NOT NULL THEN 'Attack'
        ELSE 'Normal'
    END                          AS final_target
FROM {{ source('raw', 'network_logs') }}
WHERE label_binary != 'Duplicate'