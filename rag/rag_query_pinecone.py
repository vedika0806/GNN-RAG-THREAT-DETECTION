"""
rag_query_pinecone.py

Replaces the cosine similarity SQL queries previously run in ClickHouse.
Exposes two query interfaces:
  1. query_cve_by_text()   -- natural language / attack description -> find related CVEs
  2. query_mitre_for_cve() -- given a CVE description -> find matching MITRE Techniques
                              (equivalent to the original cve_to_mitre_mapping logic)

Original ClickHouse SQL:
    SELECT cve_id, cosineDistance(description_vector, <query_vec>) AS dist
    FROM cve_mitre_master
    WHERE severity_score > 8.0 AND year = 2024
    ORDER BY dist ASC LIMIT 10

Pinecone equivalent:
    index.query(vector=query_vec, top_k=10,
                filter={"severity_score": {"$gt": 8.0}, "year": {"$eq": 2024}})

Install dependencies:
    pip install pinecone sentence-transformers
"""

import os
from pinecone import Pinecone
from sentence_transformers import SentenceTransformer
from typing import Optional

# ── Configuration ───────────────────────────────────────────────────
PINECONE_API_KEY = os.environ.get("PINECONE_API_KEY", "YOUR_PINECONE_API_KEY")
CVE_INDEX_NAME       = "cve-mitre"
MITRE_INDEX_NAME     = "mitre-reference"
MODEL_NAME           = "all-MiniLM-L6-v2"
SIMILARITY_THRESHOLD = 0.65   # Equivalent to cosine distance < 0.35 (Pinecone returns score = 1 - distance)
# ────────────────────────────────────────────────────────────────────

# Lazy-loaded globals — avoids re-initializing the model on every query call
_model = None
_pc    = None

def _get_model():
    global _model
    if _model is None:
        _model = SentenceTransformer(MODEL_NAME)
    return _model

def _get_pc():
    global _pc
    if _pc is None:
        _pc = Pinecone(api_key=PINECONE_API_KEY)
    return _pc


# ────────────────────────────────────────────────────────────────────
# Query 1: text -> related CVEs (with optional metadata filters)
# Equivalent to the ClickHouse hybrid query:
#   SELECT ... WHERE severity_score > X AND year = Y ORDER BY cosine_dist LIMIT K
# ────────────────────────────────────────────────────────────────────
def query_cve_by_text(
    query_text: str,
    top_k: int = 10,
    min_severity: Optional[float] = None,
    year: Optional[int] = None,
    mitre_id: Optional[str] = None,
) -> list[dict]:
    """
    Find the most semantically relevant CVE records for a given query string.

    Args:
        query_text:   Query string, e.g. "SQL injection remote code execution"
        top_k:        Number of top results to return
        min_severity: Minimum severity score filter (equivalent to WHERE severity_score >= X)
        year:         Filter by year (equivalent to WHERE year = X)
        mitre_id:     Filter by MITRE technique (equivalent to WHERE matched_mitre_id = 'T1190')

    Returns:
        List of dicts, each containing cve_id, similarity_score, and metadata fields.
    """
    model = _get_model()
    index = _get_pc().Index(CVE_INDEX_NAME)

    # Encode the query string into a vector
    query_vec = model.encode([query_text])[0].tolist()

    # Build Pinecone metadata filters (equivalent to SQL WHERE clauses)
    filter_dict = {}
    if min_severity is not None:
        filter_dict["severity_score"] = {"$gte": min_severity}
    if year is not None:
        filter_dict["year"] = {"$eq": year}
    if mitre_id is not None:
        filter_dict["matched_mitre_id"] = {"$eq": mitre_id}

    # Execute the vector query
    results = index.query(
        vector=query_vec,
        top_k=top_k,
        filter=filter_dict if filter_dict else None,
        include_metadata=True,
    )

    # Format output and filter out results below the similarity threshold
    output = []
    for match in results["matches"]:
        if match["score"] >= SIMILARITY_THRESHOLD:
            output.append({
                "cve_id":           match["id"],
                "similarity_score": round(match["score"], 4),
                "matched_mitre_id": match["metadata"].get("matched_mitre_id"),
                "year":             match["metadata"].get("year"),
                "severity_score":   match["metadata"].get("severity_score"),
                "description":      match["metadata"].get("description"),
            })
    return output


# ────────────────────────────────────────────────────────────────────
# Query 2: CVE description -> matching MITRE Technique
# Equivalent to the original cve_to_mitre_mapping logic in ClickHouse
# ────────────────────────────────────────────────────────────────────
def query_mitre_for_cve(
    cve_description: str,
    top_k: int = 5,
) -> list[dict]:
    """
    Given a CVE description, find the most closely matching MITRE ATT&CK Techniques.
    Applies the same threshold as the original cosineDistance < 0.35 filter.

    Args:
        cve_description: The CVE description text to query against
        top_k:           Number of candidate techniques to return

    Returns:
        List of dicts, each containing mitre_id, name, similarity_score, and description.
    """
    model = _get_model()
    index = _get_pc().Index(MITRE_INDEX_NAME)

    query_vec = model.encode([cve_description])[0].tolist()

    results = index.query(
        vector=query_vec,
        top_k=top_k,
        include_metadata=True,
    )

    output = []
    for match in results["matches"]:
        if match["score"] >= SIMILARITY_THRESHOLD:
            output.append({
                "mitre_id":         match["id"],
                "name":             match["metadata"].get("name"),
                "similarity_score": round(match["score"], 4),
                "description":      match["metadata"].get("description"),
            })
    return output


# ────────────────────────────────────────────────────────────────────
# Example usage — demonstrates the Relational Context query from the Workbook:
# "Identify all 2024 vulnerabilities exhibiting T1595 behaviors with severity > 8.0"
# ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("Example 1: Find T1595-related CVEs from 2024 with severity > 8.0")
    print("=" * 60)
    results = query_cve_by_text(
        query_text="active scanning reconnaissance network probing",
        top_k=10,
        min_severity=8.0,
        year=2024,
        mitre_id="T1595",
    )
    for r in results:
        print(f"  {r['cve_id']} | score={r['similarity_score']} | severity={r['severity_score']}")

    print("\n" + "=" * 60)
    print("Example 2: Given a CVE description, find matching MITRE Techniques")
    print("=" * 60)
    cve_desc = "A buffer overflow vulnerability allows remote attackers to execute arbitrary code via crafted SQL queries."
    mitre_matches = query_mitre_for_cve(cve_desc, top_k=3)
    for m in mitre_matches:
        print(f"  {m['mitre_id']} ({m['name']}) | score={m['similarity_score']}")
