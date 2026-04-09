-- Mirrors EDA cell 90: assign each unique IP a node_id [0..1175]
SELECT
    ip,
    (ROW_NUMBER() OVER (ORDER BY ip)) - 1 AS node_id
FROM (
    SELECT src_ip_zeek  AS ip FROM {{ ref('int_network_clean') }}
    UNION DISTINCT
    SELECT dest_ip_zeek AS ip FROM {{ ref('int_network_clean') }}
) unique_ips