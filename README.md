# GNN-RAG-THREAT-DETECTION

Team 3 | DATA 298A | SJSU Spring 2026

## Project Structure
```
├── dags/
│   └── cybersec_unified_pipeline.py
├── dbt/
│   ├── dbt_project.yml
│   ├── profiles.yml
│   └── models/
│       ├── staging/
│       │   ├── stg_network_logs.sql
│       │   ├── sources.yml
│       │   └── schema.yml
│       ├── intermediate/
│       │   └── int_network_clean.sql
│       └── marts/
│           ├── mart_node_mapping.sql
│           ├── mart_super_edges.sql
│           └── mart_gnn_ready.sql
├── data/                         # UWF parquet + combined_uwf_dataset.parquet (created by DAG)
├── .env                          (not committed)
├── docker-compose.yml
└── README.md
```

## Pipeline

UWF Zeek logs are scraped, merged to a single parquet file, loaded into **ClickHouse** database **`analytics`** as `network_logs`, then transformed with **dbt** (staging → intermediate → marts) in the same database.

## Setup

### 1. Clone the repo
```bash
git clone <repo-url>
cd GNN-RAG-THREAT-DETECTION
```

### 2. Configure ClickHouse and Airflow

- Set credentials in [dbt/profiles.yml](dbt/profiles.yml) (`cybersec_clickhouse` → `analytics` schema/database).
- Set `CLICKHOUSE_PASSWORD` in `.env` (required for Airflow load/validation tasks; `docker-compose` injects it into the container). Match the password in `profiles.yml`, or point both at the same secret.
- `dbt/target/manifest.json` is gitignored; run **dbt parse** (or **compile**) before the first DAG run so Cosmos can load the manifest.

### 3. Start Airflow
```bash
docker-compose up -d
```

### 4. Generate dbt manifest

Cosmos uses `target/manifest.json`. After any model change, re-parse or compile:

```bash
docker exec -it --user airflow <airflow-worker-container> bash -c \
  "/home/airflow/.local/bin/dbt parse \
  --project-dir /opt/Airflow/dbt \
  --profiles-dir /opt/Airflow/dbt \
  --profile cybersec_clickhouse \
  --target prod"
```

Replace `<airflow-worker-container>` with your worker service name (e.g. from `docker compose ps`).

### 5. Open Airflow UI

- URL: http://localhost:8080  
- Default: admin / admin (change in production)

### 6. Unpause and trigger the DAG
```bash
docker exec -it --user airflow <airflow-scheduler-container> \
  airflow dags unpause cybersec_unified_pipeline

docker exec -it --user airflow <airflow-scheduler-container> \
  airflow dags trigger cybersec_unified_pipeline
```

## Warehouse

- **UWF network logs** → ClickHouse Cloud, database **`analytics`** (`network_logs` raw table + dbt models).
