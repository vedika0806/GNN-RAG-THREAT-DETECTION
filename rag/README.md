# RAG Pipeline — CVE & MITRE ATT&CK Knowledge Base

This module implements the Retrieval-Augmented Generation (RAG) knowledge base for the GNN-RAG Threat Detection system. It ingests CVE vulnerability data and MITRE ATT&CK techniques into Pinecone vector indexes, enabling semantic similarity-based retrieval during GNN inference.

---

## Overview

When the Graph Attention Network (GAT) flags a suspicious network edge, the RAG pipeline retrieves the most semantically relevant CVE records and MITRE ATT&CK techniques from Pinecone. The retrieved context is passed to GPT-4o to generate a human-readable tactical threat report.

```
CVE / MITRE data
      ↓
Pre-processing & cleaning
      ↓
Sentence Transformer (all-MiniLM-L6-v2) → 384-dim vectors
      ↓
Pinecone Serverless (AWS us-east-1, cosine similarity)
      ↓
cve-mitre index (17,014 vectors)   mitre-reference index (823 vectors)
      ↓
query_cve_by_text() / query_mitre_for_cve()
      ↓
Top-K results (score ≥ 0.65) → LLM Reasoner
```

---

## Files

| File | Description |
|---|---|
| `ingest_to_pinecone.py` | Reads `CVE_MITRE_Full_Scored_Dataset.csv`, generates embeddings, and upserts all CVE records into the `cve-mitre` Pinecone index |
| `ingest_mitre_reference_pinecone.py` | Parses `enterprise-attack.json` (STIX bundle), generates embeddings, and upserts all MITRE ATT&CK techniques into the `mitre-reference` Pinecone index |
| `rag_query_pinecone.py` | Query interface — provides `query_cve_by_text()` and `query_mitre_for_cve()` functions for semantic retrieval at inference time |
| `.env.example` | Template for required environment variables |

---

## Data Sources

| Dataset | Source | Records | Format |
|---|---|---|---|
| CVE_MITRE_Full_Scored_Dataset.csv | NVD API (NIST) | 18,748 | CSV |
| enterprise-attack.json | MITRE ATT&CK STIX bundle (v18.1) | 823 techniques | JSON |

> These data files are **not included** in this repository due to size. Place them in the same directory as the scripts before running.

---

## Pinecone Index Schema

### `cve-mitre` index

| Field | Type | Description |
|---|---|---|
| `id` | String | CVE identifier (e.g. CVE-2024-1234), used as Pinecone record ID |
| `values` | Float[384] | Embedding vector generated from CVE description field |
| `matched_mitre_id` | String (metadata) | Associated MITRE ATT&CK technique (e.g. T1190) |
| `year` | Integer (metadata) | CVE publication year |
| `severity_score` | Float (metadata) | CVSS severity score (0.0–10.0) |
| `description` | String (metadata) | CVE description text (truncated to 500 chars) |

### `mitre-reference` index

| Field | Type | Description |
|---|---|---|
| `id` | String | MITRE technique ID (e.g. T1190), used as Pinecone record ID |
| `values` | Float[384] | Embedding vector generated from concatenated full_text field |
| `name` | String (metadata) | Technique name (e.g. Exploit Public-Facing Application) |
| `description` | String (metadata) | Technique description (truncated to 500 chars) |
| `full_text` | String (metadata) | Concatenated "Technique Name: ... Description: ..." (truncated to 800 chars) |

---

## Setup

### 1. Install dependencies

```bash
pip install pinecone sentence-transformers pandas tqdm
```

### 2. Set your Pinecone API key

Copy `.env.example` to `.env` and fill in your key:

```bash
cp .env.example .env
```

Or set it directly as an environment variable:

```bash
# Windows
set PINECONE_API_KEY=your_key_here

# macOS / Linux
export PINECONE_API_KEY=your_key_here
```

Get your API key from [app.pinecone.io](https://app.pinecone.io) → API Keys.

---

## Running the Ingestion Pipeline

Run the two ingestion scripts **in order**:

```bash
# Step 1 — Ingest CVE data (18,748 records, ~16 min)
python ingest_to_pinecone.py

# Step 2 — Ingest MITRE ATT&CK reference data (823 techniques, ~1 min)
python ingest_mitre_reference_pinecone.py
```

Expected output for Step 1:
```
[*] Loading SentenceTransformer model (all-MiniLM-L6-v2)...
[*] Connecting to Pinecone ...
[+] Index 'cve-mitre' created successfully.
[*] Loading dataset: CVE_MITRE_Full_Scored_Dataset.csv ...
[+] 18748 records ready for ingestion.
[*] Starting batch embedding & upsert (batch_size=100)...
Upserting: 100%|████████████████| 188/188 [15:43<00:00, 5.02s/it]
[DONE] Ingestion complete. Elapsed: 943.7s
       Total vectors in index: 17059
```

Expected output for Step 2:
```
--- Starting MITRE ATT&CK Reference Pipeline (Pinecone) ---
[+] Extracted 823 unique MITRE technique records.
[*] Loading model all-MiniLM-L6-v2...
[*] Connecting to Pinecone...
[+] Index 'mitre-reference' already exists.
Upserting MITRE: 100%|██████████| 9/9 [01:05<00:00, 7.25s/it]
[FINISH] Index 'mitre-reference' is ready. Total vectors: 823
```

---

## Using the Query Interface

Import the query functions in your inference pipeline:

```python
from rag_query_pinecone import query_mitre_for_cve, query_cve_by_text

# Find matching MITRE techniques for a CVE description
results = query_mitre_for_cve(
    "A buffer overflow allows remote attackers to execute arbitrary code.",
    top_k=3
)
# Returns: [{"mitre_id": "T1190", "name": "...", "similarity_score": 0.82, ...}]

# Find related CVEs with optional metadata filters
results = query_cve_by_text(
    query_text="active scanning reconnaissance network probing",
    top_k=10,
    min_severity=8.0,
    year=2024,
    mitre_id="T1595"
)
# Returns: [{"cve_id": "CVE-2024-...", "similarity_score": 0.79, "severity_score": 9.8, ...}]
```

### Similarity threshold

A cosine similarity threshold of **0.65** is applied to all queries (equivalent to cosine distance < 0.35). Results below this threshold are filtered out as low-confidence matches.

---

## Configuration

All configurable parameters are at the top of each script:

| Parameter | Default | Description |
|---|---|---|
| `PINECONE_API_KEY` | env var | Pinecone API key |
| `EMBEDDING_DIM` | 384 | Output dimension of all-MiniLM-L6-v2 |
| `METRIC` | cosine | Distance metric for vector search |
| `BATCH_SIZE` | 100 | Records per upsert batch |
| `SIMILARITY_THRESHOLD` | 0.65 | Minimum score to return a result |
| `MODEL_NAME` | all-MiniLM-L6-v2 | Sentence Transformer model |

---

## Notes

- The free Pinecone Serverless plan supports a maximum of **2 indexes** — both indexes in this module use the full allocation.
- The free plan is limited to the **AWS us-east-1** region, which is hardcoded in the ingestion scripts.
- Teammates only need the `PINECONE_API_KEY` to use `rag_query_pinecone.py` — they do not need to re-run the ingestion scripts.
- Raw data files (`CVE_MITRE_Full_Scored_Dataset.csv`, `enterprise-attack.json`) must be placed in the same directory as the scripts.

---

## Author

Jane Heng — DATA 298A MSDA Project I · Team 3 · May 2026
