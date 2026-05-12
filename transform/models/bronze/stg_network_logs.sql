{{
    config(
        materialized='table',
        schema='RAW',
        tags=['bronze'],
        comment='Bronze: raw UWF Zeek network logs as ingested by Airflow. No transforms applied.'
    )
}}

SELECT
    -- Connection identifiers
    uid,
    community_id,
    ts,
    datetime,
    source_period,

    -- Network topology
    src_ip_zeek,
    dest_ip_zeek,
    src_port_zeek,
    dest_port_zeek,

    -- Protocol metadata
    proto,
    service,
    conn_state,
    history,

    -- Traffic volume (raw — log-scaling happens in Silver)
    duration,
    orig_bytes,
    resp_bytes,
    orig_pkts,
    resp_pkts,
    orig_ip_bytes,
    resp_ip_bytes,
    missed_bytes,

    -- Locality flags
    local_orig,
    local_resp,

    -- Network metadata
    vlan,

    -- Labels
    label_tactic,
    label_technique,
    label_binary,
    label_cve,

    -- Ingestion metadata added by Airflow
    _ingested_at,
    _source_file

FROM {{ source('raw', 'NETWORK_LOGS_RAW') }}

WHERE
    -- Guard against Airflow partial loads writing empty rows
    uid IS NOT NULL
    AND src_ip_zeek IS NOT NULL
    AND dest_ip_zeek IS NOT NULL
