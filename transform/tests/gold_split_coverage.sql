-- Singular test: All three splits must be populated.
-- Fails if hash-based split assigns all edges to one partition.

SELECT split, COUNT(*) AS cnt
FROM {{ ref('gnn_edge_attr') }}
GROUP BY split
HAVING COUNT(*) = 0
