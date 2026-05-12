"""
ingest_to_pinecone.py
Replaces the original ingest_to_clickhouse.py

Reads CVE_MITRE_Full_Scored_Dataset.csv, generates 384-dim embeddings,
and batch-upserts all records into a Pinecone Index.

Install dependencies:
    pip install pinecone sentence-transformers pandas tqdm
"""

import os
import time
import pandas as pd
from tqdm import tqdm
from pinecone import Pinecone, ServerlessSpec
from sentence_transformers import SentenceTransformer

# ── Configuration (only edit this section) ──────────────────────────
PINECONE_API_KEY = os.environ.get("PINECONE_API_KEY", "YOUR_PINECONE_API_KEY")
INDEX_NAME       = "cve-mitre"               # Index name, customizable
EMBEDDING_DIM    = 384                        # Output dimension of all-MiniLM-L6-v2
METRIC           = "cosine"                   # Matches the cosine distance used in ClickHouse
BATCH_SIZE       = 100                        # Recommended batch size for Pinecone free tier
CSV_PATH         = "CVE_MITRE_Full_Scored_Dataset.csv"
MODEL_NAME       = "all-MiniLM-L6-v2"
# ────────────────────────────────────────────────────────────────────


def build_index(pc: Pinecone) -> object:
    """Create the Pinecone Index if it does not already exist (Serverless free tier)."""
    existing = [idx.name for idx in pc.list_indexes()]
    if INDEX_NAME not in existing:
        print(f"[*] Creating Pinecone Index: {INDEX_NAME} ...")
        pc.create_index(
            name=INDEX_NAME,
            dimension=EMBEDDING_DIM,
            metric=METRIC,
            spec=ServerlessSpec(cloud="aws", region="us-east-1"),  # Fixed region for free tier
        )
        # Wait until the Index is ready before returning
        while not pc.describe_index(INDEX_NAME).status["ready"]:
            print("    Waiting for Index to become ready...")
            time.sleep(3)
        print(f"[+] Index '{INDEX_NAME}' created successfully.")
    else:
        print(f"[+] Index '{INDEX_NAME}' already exists, skipping creation.")
    return pc.Index(INDEX_NAME)


def run_ingestion():
    if not os.path.exists(CSV_PATH):
        print(f"[ERROR] File not found: {CSV_PATH}")
        return

    # Step 1: Load the embedding model
    print(f"[*] Loading SentenceTransformer model ({MODEL_NAME})...")
    model = SentenceTransformer(MODEL_NAME)

    # Step 2: Connect to Pinecone
    print("[*] Connecting to Pinecone ...")
    pc = Pinecone(api_key=PINECONE_API_KEY)
    index = build_index(pc)

    # Step 3: Load and clean the CSV dataset
    print(f"[*] Loading dataset: {CSV_PATH} ...")
    df = pd.read_csv(CSV_PATH)
    df["severity_score"] = df["severity_score"].fillna(0.0).astype(float)
    df["year"]            = df["year"].fillna(2026).astype(int)
    df["description"]     = df["description"].fillna("").astype(str)
    print(f"[+] {len(df)} records ready for ingestion.")

    # Step 4: Generate embeddings in batches and upsert to Pinecone
    print(f"[*] Starting batch embedding & upsert (batch_size={BATCH_SIZE})...")
    start = time.time()

    for batch_start in tqdm(range(0, len(df), BATCH_SIZE), desc="Upserting"):
        batch = df.iloc[batch_start : batch_start + BATCH_SIZE]

        descriptions = batch["description"].tolist()
        vectors      = model.encode(descriptions, show_progress_bar=False).tolist()

        # Build the Pinecone upsert payload:
        # [
        #   {
        #     "id": "CVE-2024-1234",        # Unique record ID -> use cve_id
        #     "values": [0.12, -0.34, ...], # 384-dim embedding vector
        #     "metadata": {                  # Filterable fields (replaces SQL WHERE clauses)
        #       "matched_mitre_id": "T1190",
        #       "year": 2024,
        #       "severity_score": 8.5,
        #       "description": "..."
        #     }
        #   },
        #   ...
        # ]
        upsert_payload = [
            {
                "id": str(row["cve_id"]),
                "values": vec,
                "metadata": {
                    "matched_mitre_id": str(row["matched_mitre_id"]),
                    "year":             int(row["year"]),
                    "severity_score":   float(row["severity_score"]),
                    "description":      str(row["description"])[:500],  # Truncated to stay well under the 40KB metadata limit
                },
            }
            for row, vec in zip(batch.to_dict("records"), vectors)
        ]

        index.upsert(vectors=upsert_payload)

    elapsed = time.time() - start
    stats = index.describe_index_stats()
    print(f"\n[DONE] Ingestion complete. Elapsed: {elapsed:.1f}s")
    print(f"       Total vectors in index: {stats['total_vector_count']}")


if __name__ == "__main__":
    run_ingestion()
