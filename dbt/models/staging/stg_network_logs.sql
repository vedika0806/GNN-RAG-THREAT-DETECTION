-- Cleaned UWF network logs: dedupe, final_target, vlan normalization (ClickHouse)
SELECT
    uid,
    src_ip_zeek,
    dest_ip_zeek,
    src_port_zeek,
    dest_port_zeek,
    proto,
    service,
    coalesce(duration, 0) AS duration,
    coalesce(orig_bytes, 0) AS orig_bytes,
    coalesce(resp_bytes, 0) AS resp_bytes,
    orig_pkts,
    resp_pkts,
    orig_ip_bytes,
    resp_ip_bytes,
    missed_bytes,
    conn_state,
    coalesce(history, '-') AS history,
    multiIf(
        vlan IS NULL OR vlan = 'unknown' OR vlan = 'NaN',
        'none',
        toString(toInt32(round(toFloat32OrZero(toString(vlan)))))
    ) AS vlan,
    label_tactic,
    label_technique,
    source_period,
    datetime,
    ts,
    multiIf(
        label_tactic != 'none' AND label_tactic IS NOT NULL,
        'Attack',
        'Normal'
    ) AS final_target
FROM {{ source('raw', 'network_logs') }}
WHERE label_binary != 'Duplicate'
