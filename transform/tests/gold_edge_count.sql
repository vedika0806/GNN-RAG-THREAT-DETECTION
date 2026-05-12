-- Singular test: Gold edge table must have at least 2183 edges.
-- Using >= to allow new data periods to add edges without breaking the test.

SELECT COUNT(*) AS edge_count
FROM {{ ref('gnn_edge_attr') }}
HAVING COUNT(*) < 2183
