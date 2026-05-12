{{
    config(
        materialized='table',
        schema='SILVER',
        tags=['silver'],
        comment='Silver: deterministic IP string → integer node ID mapping (0..N-1). Stable across runs.'
    )
}}

-- Collect every unique IP from both source and destination.
-- ROW_NUMBER ordered by IP string ensures the mapping is stable across runs
-- as long as no new IPs appear (new IPs will get appended node IDs).
WITH unique_ips AS (
    SELECT src_ip_zeek AS ip FROM {{ ref('network_logs_clean') }}
    UNION
    SELECT dest_ip_zeek AS ip FROM {{ ref('network_logs_clean') }}
)

SELECT
    ip,
    ROW_NUMBER() OVER (ORDER BY ip) - 1 AS node_id,
    -- Flag local IPs for use as a node feature in Gold layer.
    -- RFC1918 private ranges: 10.0.0.0/8, 172.16.0.0/12 (172.16-31), 192.168.0.0/16
    -- The 172.16-31 range cannot be expressed with a simple LIKE; we extract the second
    -- octet numerically so we don't accidentally include 172.10-15 or 172.32-39.
    CASE
        WHEN ip LIKE '10.%'
          OR (ip LIKE '172.%'
              AND TRY_CAST(SPLIT_PART(ip, '.', 2) AS INTEGER) BETWEEN 16 AND 31)
          OR ip LIKE '192.168.%'
          OR ip LIKE '143.88.%'  -- UWF campus network
          OR ip = '127.0.0.1'
        THEN 1
        ELSE 0
    END AS is_local

FROM unique_ips
