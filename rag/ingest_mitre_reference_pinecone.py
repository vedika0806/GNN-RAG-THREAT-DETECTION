"""
ingest_mitre_reference_pinecone.py
Replaces the original ingest_mitre_reference.py

Parses enterprise-attack.json, generates embeddings, and writes all
MITRE ATT&CK technique records into a Pinecone Index.
Data previously stored in the ClickHouse table mitre_attack_reference
is now stored as vectors in the Pinecone Index "mitre-reference".

Install dependencies:
    pip install pinecone sentence-transformers tqdm
"""

import os
import json
import time
import pandas as pd
from tqdm import tqdm
from pinecone import Pinecone, ServerlessSpec
from sentence_transformers import SentenceTransformer

# ── Configuration ───────────────────────────────────────────────────
PINECONE_API_KEY = os.environ.get("PINECONE_API_KEY", "YOUR_PINECONE_API_KEY")
INDEX_NAME       = "mitre-reference"
EMBEDDING_DIM    = 384
METRIC           = "cosine"
BATCH_SIZE       = 100
JSON_PATH        = "enterprise-attack.json"
MODEL_NAME       = "all-MiniLM-L6-v2"
# ────────────────────────────────────────────────────────────────────


def build_index(pc: Pinecone) -> object:
    existing = [idx.name for idx in pc.list_indexes()]
    if INDEX_NAME not in existing:
        print(f"[*] Creating Pinecone Index: {INDEX_NAME} ...")
        pc.create_index(
            name=INDEX_NAME,
            dimension=EMBEDDING_DIM,
            metric=METRIC,
            spec=ServerlessSpec(cloud="aws", region="us-east-1"),
        )
        while not pc.describe_index(INDEX_NAME).status["ready"]:
            print("    Waiting for Index to become ready...")
            time.sleep(3)
        print(f"[+] Index '{INDEX_NAME}' created successfully.")
    else:
        print(f"[+] Index '{INDEX_NAME}' already exists.")
    return pc.Index(INDEX_NAME)


def parse_mitre_json(json_path: str) -> pd.DataFrame:
    """Parse the STIX bundle. Logic is identical to the original script."""
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    records = []
    for obj in data.get("objects", []):
        if obj.get("type") == "attack-pattern" and not obj.get("x_mitre_deprecated"):
            mitre_id = ""
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    mitre_id = ref.get("external_id", "")
            name        = obj.get("name", "")
            description = obj.get("description", "")
            if mitre_id:
                full_text = f"Technique Name: {name}. Description: {description}"
                records.append({
                    "mitre_id":    mitre_id,
                    "name":        name,
                    "description": description,
                    "full_text":   full_text,
                })

    df = pd.DataFrame(records)
    print(f"[+] Extracted {len(df)} unique MITRE technique records.")
    return df


def ingest_mitre_reference():
    print("--- Starting MITRE ATT&CK Reference Pipeline (Pinecone) ---")

    # Step 1: Parse the STIX JSON bundle
    df = parse_mitre_json(JSON_PATH)

    # Step 2: Load the embedding model
    print(f"[*] Loading model {MODEL_NAME}...")
    model = SentenceTransformer(MODEL_NAME)

    # Step 3: Connect to Pinecone
    print("[*] Connecting to Pinecone...")
    pc    = Pinecone(api_key=PINECONE_API_KEY)
    index = build_index(pc)

    # Step 4: Refresh data — equivalent to TRUNCATE TABLE + INSERT in ClickHouse
    # On first run the index is empty, so delete_all raises 404 — safely ignore it
    print("[*] Clearing existing data (equivalent to TRUNCATE TABLE)...")
    try:
        index.delete(delete_all=True)
        time.sleep(2)  # Wait for the deletion to propagate
    except Exception:
        print("[*] Index is empty, skipping delete.")

    # Step 5: Generate embeddings in batches and upsert
    print(f"[*] Starting batch embedding & upsert (batch_size={BATCH_SIZE})...")
    for batch_start in tqdm(range(0, len(df), BATCH_SIZE), desc="Upserting MITRE"):
        batch   = df.iloc[batch_start : batch_start + BATCH_SIZE]
        vectors = model.encode(batch["full_text"].tolist(), show_progress_bar=False).tolist()

        # Use mitre_id (e.g. T1190) as the Pinecone record ID — naturally unique
        upsert_payload = [
            {
                "id":     str(row["mitre_id"]),
                "values": vec,
                "metadata": {
                    "mitre_id":    str(row["mitre_id"]),
                    "name":        str(row["name"]),
                    "description": str(row["description"])[:500],
                    "full_text":   str(row["full_text"])[:800],
                },
            }
            for row, vec in zip(batch.to_dict("records"), vectors)
        ]
        index.upsert(vectors=upsert_payload)

    stats = index.describe_index_stats()
    print(f"\n[FINISH] Index 'mitre-reference' is ready. Total vectors: {stats['total_vector_count']}")


if __name__ == "__main__":
    ingest_mitre_reference()
