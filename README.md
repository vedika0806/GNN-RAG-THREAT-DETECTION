# GNN-RAG-THREAT-DETECTION

Team 3 | DATA 298A | SJSU Spring 2026

## Project Structure
```
Airflow/
├── dags/
│   └── cybersec_unified_pipeline.py
├── dbt/
│   ├── dbt_project.yml
│   ├── profiles.yml
│   ├── sources.yml
│   └── models/
│       ├── staging/
│       │   ├── stg_network_logs.sql
│       │   ├── stg_cve_mitre.sql
│       │   └── schema.yml
│       ├── intermediate/
│       │   ├── int_network_clean.sql
│       │   └── int_cve_enriched.sql
│       └── marts/
│           ├── mart_node_mapping.sql
│           ├── mart_super_edges.sql
│           ├── mart_gnn_ready.sql
│           └── mart_cve_threat_index.sql
├── data/
│   └── CVE_MITRE_Full_Scored_Dataset.csv
├── .env                          (not committed)
├── .env.example
├── .gitignore
├── docker-compose.yml
└── README.md

## Setup

### 1. Clone the repo
```bash
git clone <repo-url>
cd Airflow
```

### 2. Create your .env file
```bash
cp .env.example .env
# Fill in your ClickHouse credentials
```

### 3. Add your CVE file
Copy CVE_MITRE_Full_Scored_Dataset.csv into the data/ folder

### 4. Start Airflow
```bash
docker-compose up -d
```

### 5. Generate dbt manifest
```bash
docker exec -it --user airflow airflow-airflow-worker-1 bash -c \
  "/home/airflow/.local/bin/dbt compile \
  --project-dir /opt/Airflow/dbt \
  --profiles-dir /opt/Airflow/dbt \
  --profile cybersec_duckdb \
  --target prod"
```

### 6. Open Airflow UI
- URL: http://localhost:8080
- Username: admin
- Password: admin

### 7. Unpause and trigger the DAG
```bash
docker exec -it --user airflow airflow-airflow-scheduler-1 \
  airflow dags unpause cybersec_unified_pipeline

docker exec -it --user airflow airflow-airflow-scheduler-1 \
  airflow dags trigger cybersec_unified_pipeline
```

## Warehouses
- **UWF Network Logs** → DuckDB (local file)
- **CVE-MITRE** → ClickHouse Cloud
