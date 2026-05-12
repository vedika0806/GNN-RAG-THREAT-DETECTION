-- Singular test: Gold node feature table must have exactly 1176 nodes.
-- If this fails, a new IP appeared in the data or the node_mapping is broken.

SELECT COUNT(*) AS node_count
FROM {{ ref('gnn_node_features') }}
HAVING COUNT(*) != 1176
