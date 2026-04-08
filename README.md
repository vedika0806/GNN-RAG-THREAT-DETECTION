# GNN-RAG-THREAT-DETECTION

Team 3 | DATA 298A | SJSU Spring 2026

## Project Structure
cybersec_pipeline/
├── dags/                          # Airflow DAG
├── dbt/                           # dbt transformation models
│   ├── models/
│   │   ├── staging/
│   │   ├── intermediate/
│   │   └── marts/
│   ├── dbt_project.yml
│   ├── profiles.yml
│   └── sources.yml
├── data/                          # Input data (UWF_Data auto-created)
├── docker-compose.yml
└── .env                           # Not committed — see setup below

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
