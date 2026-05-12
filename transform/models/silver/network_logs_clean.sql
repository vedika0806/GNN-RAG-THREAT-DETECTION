{{
    config(
        materialized='table',
        schema='SILVER',
        tags=['silver'],
        comment='Silver: deduped, labeled, imputed network logs. Single source of truth for Gold layer.'
    )
}}

WITH base AS (
    SELECT * FROM {{ ref('stg_network_logs') }}
    -- Remove rows flagged as duplicates by the source labeling system
    WHERE label_binary != 'Duplicate'
),

labeled AS (
    SELECT
        *,
        -- Authoritative binary target derived from label_tactic (consistent across all dataset years)
        CASE
            WHEN label_tactic IS NOT NULL AND label_tactic != 'none' THEN 'Attack'
            ELSE 'Normal'
        END AS final_target,

        -- Technique normalization: preserve tactic context for unknowns (no hallucination)
        CASE
            WHEN label_tactic != 'none' AND label_technique IN ('unknown', NULL)
                THEN label_tactic || '_unspecified'
            WHEN label_tactic IS NULL OR label_tactic = 'none'
                THEN 'none'
            ELSE label_technique
        END AS label_technique_clean

    FROM base
),

vlan_normalized AS (
    SELECT
        *,
        -- Standardize VLAN: remove float artifacts (105.0 → 105), sentinel for missing
        CASE
            WHEN vlan IS NULL OR vlan IN ('unknown', 'NaN', 'nan')
                THEN 'none'
            ELSE TRUNC(TRY_CAST(vlan AS FLOAT))::INTEGER::VARCHAR
        END AS vlan_clean
    FROM labeled
),

imputed AS (
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
        COALESCE(service, 'unknown') AS service,
        conn_state,
        COALESCE(history, '-') AS history,

        -- Traffic volume with proper imputation:
        -- NULL in Zeek = in-progress or incomplete log, NOT a zero-byte transfer.
        -- We impute with column median and add a boolean indicator so the GNN
        -- can distinguish "genuinely small" from "unknown."
        CASE
            WHEN duration IS NULL THEN {{ var('median_duration') }}
            ELSE duration
        END AS duration,
        (duration IS NOT NULL) AS duration_known,

        CASE
            WHEN orig_bytes IS NULL THEN {{ var('median_orig_bytes') }}
            ELSE orig_bytes
        END AS orig_bytes,
        (orig_bytes IS NOT NULL) AS bytes_known,

        CASE
            WHEN resp_bytes IS NULL THEN {{ var('median_resp_bytes') }}
            ELSE resp_bytes
        END AS resp_bytes,

        orig_pkts,
        resp_pkts,
        orig_ip_bytes,
        resp_ip_bytes,
        COALESCE(missed_bytes, 0) AS missed_bytes,

        -- Locality flags (cast to integer for GNN compatibility)
        COALESCE(local_orig::INTEGER, 0) AS local_orig,
        COALESCE(local_resp::INTEGER, 0) AS local_resp,

        -- Normalized VLAN
        vlan_clean AS vlan,

        -- Labels
        label_tactic,
        label_technique_clean AS label_technique,
        final_target,

        -- Ingestion lineage
        _ingested_at,
        _source_file

    FROM vlan_normalized
)

-- Deduplicate: keep one row per (uid, source_period).
-- Zeek UIDs are unique within a single capture session but can repeat across
-- weekly source_period windows — those cross-period rows are legitimately
-- distinct connections and are preserved.  Within the same period, any
-- remaining duplicates (label_binary filter didn't catch everything) are
-- resolved by keeping the latest-ingested copy.
SELECT * FROM imputed
QUALIFY ROW_NUMBER() OVER (
    PARTITION BY uid, source_period
    ORDER BY _ingested_at DESC
) = 1
