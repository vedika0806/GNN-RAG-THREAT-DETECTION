-- Singular test: Silver must have no duplicate (uid, source_period) pairs.
-- Zeek UIDs are only guaranteed unique within a single capture session
-- (source_period). The same UID can legitimately appear in a different
-- source_period (different week's Zeek instance). We deduplicate within
-- each period using QUALIFY in the Silver model, so this check verifies
-- that deduplication is clean inside each period.

SELECT uid, source_period, COUNT(*) AS cnt
FROM {{ ref('network_logs_clean') }}
GROUP BY uid, source_period
HAVING COUNT(*) > 1
