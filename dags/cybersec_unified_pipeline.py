# =============================================================================
# cybersec_unified_pipeline.py
#
# Unified Airflow DAG — GraphRAG Cybersecurity Threat Intelligence System
# Team 3 | DATA 298A
#
# Two parallel pipelines orchestrated in one DAG:
#   1. UWF Network Logs  → Web scrape → Combine Parquet → DuckDB → dbt models
#   2. CVE-MITRE         → CSV ingest → ClickHouse      → dbt models
#
# Both pipelines converge at a shared validation + summary step.
# Each dbt model appears as its own task in Airflow via astronomer-cosmos.
#
# Required pip packages (add to docker-compose _PIP_ADDITIONAL_REQUIREMENTS):
#   dbt-duckdb dbt-clickhouse astronomer-cosmos duckdb
#   clickhouse-connect pandas beautifulsoup4 requests fastparquet
# =============================================================================

from __future__ import annotations

import glob
import logging
import os
import time
from datetime import timedelta, datetime
from pathlib import Path

import duckdb
import pandas as pd
import requests
import clickhouse_connect
from bs4 import BeautifulSoup
from fastparquet import write as fp_write

from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.utils.dates import days_ago
from airflow.utils.task_group import TaskGroup

from cosmos import DbtTaskGroup, ExecutionConfig, ProfileConfig, ProjectConfig, RenderConfig
from cosmos.constants import LoadMode

# =============================================================================
# CONFIGURATION — update these before running
# =============================================================================

# UWF
UWF_BASE_URL   = "https://datasets.uwf.edu/data/"
DATA_DIR       = "/opt/airflow/data"
UWF_RAW_DIR    = f"{DATA_DIR}/UWF_Data"
PARQUET_FILE   = f"{UWF_RAW_DIR}/combined_uwf_dataset.parquet"
DUCKDB_FILE    = f"{UWF_RAW_DIR}/uwf_cybersecurity.db"

# CVE
CVE_CSV_PATH   = f"{DATA_DIR}/CVE_MITRE_Full_Scored_Dataset.csv"
CH_HOST        = "<your-host>.clickhouse.cloud"   # ← update
CH_USER        = "default"
CH_PASSWORD    = "<your-password>"                # ← update

# dbt
DBT_PROJECT_PATH = Path("/opt/Airflow/dbt")

# Columns added in later UWF dataset versions — missing in older parquet files
UWF_NEW_COLS = ["label_technique", "label_cve", "label_binary", "vlan"]

# =============================================================================
# COSMOS PROFILE CONFIGS
#
# Both pipelines read credentials directly from profiles.yml on disk.
# cosmos profile mappings are NOT used — the installed cosmos version does
# not ship DuckDB or ClickHouse profile mapping classes.
#
# No Airflow Connections are needed for dbt model execution.
# Make sure /opt/airflow/dbt_cybersec/profiles.yml has correct credentials
# for both cybersec_duckdb and cybersec_clickhouse before triggering the DAG.
# =============================================================================

uwf_profile_config = ProfileConfig(
    profile_name="cybersec_duckdb",
    target_name="prod",
    profiles_yml_filepath=DBT_PROJECT_PATH / "profiles.yml",
)

cve_profile_config = ProfileConfig(
    profile_name="cybersec_clickhouse",
    target_name="prod",
    profiles_yml_filepath=DBT_PROJECT_PATH / "profiles.yml",
)

# =============================================================================
# DEFAULT ARGS
# =============================================================================

default_args = {
    "owner": "team3",
    "retries": 2,
    "retry_delay": timedelta(minutes=3),
    "email_on_failure": False,
}

# =============================================================================
# ── TASK FUNCTIONS : UWF PIPELINE ────────────────────────────────────────────
# =============================================================================

def scrape_uwf_parquet(**context):
    """
    Task 1 (UWF): Scrape parquet files from the UWF dataset portal.
    Mirrors Notebook 1 — scrape_datasets() function.
    Skips files that already exist locally (idempotent).
    Source: https://datasets.uwf.edu/data/
    Datasets: UWF-ZeekData22, UWF-ZeekData24, UWF-ZeekDataFall22,
              UWF-ZeekDataFall24-2, UWF-ZeekDataSum25-1, UWF-ZeekDataSum25-2
    """
    os.makedirs(UWF_RAW_DIR, exist_ok=True)
    downloaded = []

    def scrape(url, local_path):
        time.sleep(1)  # polite crawl delay
        try:
            response = requests.get(url, timeout=10)
            soup = BeautifulSoup(response.text, "html.parser")
        except Exception as e:
            logging.error(f"Failed to access {url}: {e}")
            return

        for link in soup.find_all("a"):
            href = link.get("href", "")

            # Skip navigation and non-data links
            if href in ["../", "SUCCESS", "_SUCCESS"] or "?" in href:
                continue

            full_url = url + href

            if href.endswith("/"):
                # Skip CSV metric folders — only want parquet data
                if "csv" in href.lower():
                    continue
                new_local_path = os.path.join(local_path, href.strip("/"))
                os.makedirs(new_local_path, exist_ok=True)
                scrape(full_url, new_local_path)

            elif href.startswith("part-") and "parquet" in url.lower():
                local_file = os.path.join(local_path, href)
                if not os.path.exists(local_file):
                    logging.info(f"Downloading: {href}")
                    try:
                        with requests.get(full_url, stream=True) as r:
                            r.raise_for_status()
                            with open(local_file, "wb") as f:
                                for chunk in r.iter_content(chunk_size=8192):
                                    f.write(chunk)
                        downloaded.append(local_file)
                    except Exception as e:
                        logging.error(f"Failed to download {href}: {e}")

    scrape(UWF_BASE_URL, UWF_RAW_DIR)
    logging.info(f"Scrape complete. Downloaded {len(downloaded)} new parquet files.")
    context["ti"].xcom_push(key="new_files_downloaded", value=len(downloaded))


def combine_parquet_files(**context):
    """
    Task 2 (UWF): Combine all individual period parquet files into one
    master parquet file — combined_uwf_dataset.parquet.
    Mirrors Notebook 1 — merge_parquets_to_disk() function.

    Key logic:
    - Columns vary across years (23 to 27 columns)
    - Missing columns (label_technique, label_cve, label_binary, vlan)
      are filled with 'unknown' for older datasets
    - source_period column added to track which period each row came from
    """
    search_pattern = os.path.join(
        UWF_RAW_DIR, "**", "parquet", "**", "part-*.parquet"
    )
    files = glob.glob(search_pattern, recursive=True)

    if not files:
        raise FileNotFoundError(
            f"No parquet files found under {UWF_RAW_DIR}. "
            "Check that scrape_uwf_parquet ran successfully."
        )

    logging.info(f"Found {len(files)} parquet files to combine.")

    # Remove existing combined file to rebuild fresh
    if os.path.exists(PARQUET_FILE):
        os.remove(PARQUET_FILE)
        logging.info("Removed existing combined_uwf_dataset.parquet")

    first_file = True
    for i, file_path in enumerate(files):
        try:
            df = pd.read_parquet(file_path, engine="fastparquet")

            # Tag with source period (folder name = date range)
            folder_name = os.path.basename(os.path.dirname(file_path))
            df["source_period"] = folder_name

            # Normalize schema: add missing columns as 'unknown'
            for col in UWF_NEW_COLS:
                if col not in df.columns:
                    df[col] = "unknown"
                else:
                    # Force string and replace NaN artifacts
                    df[col] = df[col].astype(str).replace("nan", "unknown")

            if first_file:
                fp_write(PARQUET_FILE, df, compression="SNAPPY")
                first_file = False
                logging.info(f"Initialized master parquet from: {folder_name}")
            else:
                fp_write(PARQUET_FILE, df, append=True, compression="SNAPPY")

            if i % 10 == 0:
                logging.info(f"Progress: {i}/{len(files)} files combined.")

        except Exception as e:
            logging.error(f"Error processing {file_path}: {e}")

    logging.info(f"Combined parquet saved to: {PARQUET_FILE}")
    context["ti"].xcom_push(key="files_combined", value=len(files))


def load_combined_parquet_to_duckdb(**context):
    """
    Task 3 (UWF): Load combined_uwf_dataset.parquet into DuckDB as
    the raw network_logs table.
    Mirrors EDA Notebook — CREATE TABLE + INSERT FROM read_parquet().
    Schema: 28 columns as defined in EDA Notebook cell 35.
    """
    if not os.path.exists(PARQUET_FILE):
        raise FileNotFoundError(
            f"Combined parquet not found at {PARQUET_FILE}. "
            "Ensure combine_parquet_files ran successfully."
        )

    con = duckdb.connect(DUCKDB_FILE)

    # Drop and recreate for idempotency
    con.execute("DROP TABLE IF EXISTS network_logs")
    con.execute("""
        CREATE TABLE network_logs (
            resp_pkts       BIGINT,
            service         VARCHAR,
            orig_ip_bytes   BIGINT,
            local_resp      BOOLEAN,
            missed_bytes    BIGINT,
            proto           VARCHAR,
            duration        DOUBLE,
            conn_state      VARCHAR,
            dest_ip_zeek    VARCHAR,
            orig_pkts       BIGINT,
            community_id    VARCHAR,
            resp_ip_bytes   BIGINT,
            dest_port_zeek  INTEGER,
            orig_bytes      BIGINT,
            local_orig      BOOLEAN,
            datetime        TIMESTAMP,
            history         VARCHAR,
            resp_bytes      BIGINT,
            uid             VARCHAR,
            src_port_zeek   INTEGER,
            ts              DOUBLE,
            src_ip_zeek     VARCHAR,
            label_tactic    VARCHAR,
            source_period   VARCHAR,
            label_technique VARCHAR,
            label_cve       VARCHAR,
            label_binary    VARCHAR,
            vlan            VARCHAR
        )
    """)

    con.execute(f"""
        INSERT INTO network_logs
        SELECT * FROM read_parquet('{PARQUET_FILE}')
    """)

    count = con.execute("SELECT COUNT(*) FROM network_logs").fetchone()[0]
    logging.info(f"Loaded {count:,} rows into DuckDB network_logs table.")
    con.close()

    context["ti"].xcom_push(key="raw_uwf_count", value=count)


def validate_uwf_raw(**context):
    """
    Task 4 (UWF): Validate the raw DuckDB table has expected row count
    and all required columns are present before dbt runs.
    """
    con = duckdb.connect(DUCKDB_FILE)

    count = con.execute("SELECT COUNT(*) FROM network_logs").fetchone()[0]
    logging.info(f"Raw row count: {count:,}")

    cols = {
        r[0]
        for r in con.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = 'network_logs'"
        ).fetchall()
    }
    con.close()

    required = {
        "src_ip_zeek", "dest_ip_zeek", "proto",
        "label_tactic", "label_binary", "source_period",
    }
    missing = required - cols
    if missing:
        raise ValueError(f"Raw validation FAILED — missing columns: {missing}")

    if count < 20_000_000:
        raise ValueError(
            f"Raw validation FAILED — row count {count:,} is suspiciously low. "
            "Expected ~27M rows."
        )

    logging.info("UWF raw validation PASSED.")


# =============================================================================
# ── TASK FUNCTIONS : CVE PIPELINE ────────────────────────────────────────────
# =============================================================================

def validate_cve_source(**context):
    """
    Task 1 (CVE): Validate the CVE CSV file exists and has the
    expected columns before ingestion.
    """
    if not os.path.exists(CVE_CSV_PATH):
        raise FileNotFoundError(
            f"CVE CSV not found at {CVE_CSV_PATH}. "
            "Ensure the file is mounted at /opt/airflow/data/"
        )

    df = pd.read_csv(CVE_CSV_PATH, nrows=5)
    required = {"cve_id", "matched_mitre_id", "year", "severity_score", "description"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"CVE CSV is missing columns: {missing}")

    logging.info(f"CVE source validation PASSED. Columns: {list(df.columns)}")


def ingest_cve_to_clickhouse(**context):
    """
    Task 2 (CVE): Batch load the CVE-MITRE CSV into ClickHouse Cloud
    as the raw cve_mitre_master table.
    Mirrors ingest_to_clickhouse.py — batch size 500, idempotent via TRUNCATE.
    """
    client = clickhouse_connect.get_client(
        host=CH_HOST,
        user=CH_USER,
        password=CH_PASSWORD,
        secure=True,
    )

    # Create table if it doesn't exist
    client.command("""
        CREATE TABLE IF NOT EXISTS default.cve_mitre_master (
            matched_mitre_id  String,
            cve_id            String,
            year              UInt16,
            severity_score    Float32,
            description       String
        ) ENGINE = MergeTree()
        ORDER BY cve_id
    """)

    # Truncate for idempotency — full reload each run
    client.command("TRUNCATE TABLE IF EXISTS default.cve_mitre_master")
    logging.info("Truncated cve_mitre_master for fresh load.")

    df = pd.read_csv(CVE_CSV_PATH)
    df = df[["matched_mitre_id", "cve_id", "year", "severity_score", "description"]]
    df = df.dropna(subset=["cve_id"])

    total = 0
    batch_size = 500
    for i in range(0, len(df), batch_size):
        chunk = df.iloc[i : i + batch_size]
        client.insert_df("default.cve_mitre_master", chunk)
        total += len(chunk)

    logging.info(f"Ingested {total:,} CVE records into ClickHouse.")
    context["ti"].xcom_push(key="cve_ingested_count", value=total)


# =============================================================================
# ── TASK FUNCTIONS : POST-PIPELINE VALIDATION ────────────────────────────────
# =============================================================================

def validate_uwf_marts(**context):
    """
    Task (Convergence): Validate dbt UWF marts were built correctly.
    Checks:
      - mart_node_mapping  → exactly 1,176 unique IP nodes
      - mart_super_edges   → exactly 2,183 directed edges
      - mart_gnn_ready     → train/test split present, rows > 0
    """
    con = duckdb.connect(DUCKDB_FILE)

    nodes = con.execute("SELECT COUNT(*) FROM mart_node_mapping").fetchone()[0]
    edges = con.execute("SELECT COUNT(*) FROM mart_super_edges").fetchone()[0]
    gnn   = con.execute("SELECT COUNT(*) FROM mart_gnn_ready").fetchone()[0]
    train = con.execute(
        "SELECT COUNT(*) FROM mart_gnn_ready WHERE split_mask = 'train'"
    ).fetchone()[0]
    test  = con.execute(
        "SELECT COUNT(*) FROM mart_gnn_ready WHERE split_mask = 'test'"
    ).fetchone()[0]
    con.close()

    logging.info(f"UWF marts — nodes: {nodes}, edges: {edges}, "
                 f"gnn_ready: {gnn} (train: {train}, test: {test})")

    if nodes != 1176:
        raise ValueError(f"Node count mismatch: expected 1176, got {nodes}")
    if edges == 0:
        raise ValueError("mart_super_edges is empty — dbt models may have failed.")
    if gnn == 0:
        raise ValueError("mart_gnn_ready is empty.")

    logging.info("UWF mart validation PASSED.")
    context["ti"].xcom_push(key="uwf_nodes", value=nodes)
    context["ti"].xcom_push(key="uwf_edges", value=edges)
    context["ti"].xcom_push(key="uwf_gnn_rows", value=gnn)
    context["ti"].xcom_push(key="uwf_train_rows", value=train)
    context["ti"].xcom_push(key="uwf_test_rows", value=test)


def validate_cve_mart(**context):
    """
    Task (Convergence): Validate the ClickHouse CVE mart table
    was populated correctly after dbt run.
    """
    client = clickhouse_connect.get_client(
        host=CH_HOST,
        user=CH_USER,
        password=CH_PASSWORD,
        secure=True,
    )

    count = client.query(
        "SELECT count() FROM default.mart_cve_threat_index"
    ).result_rows[0][0]

    logging.info(f"CVE mart — mart_cve_threat_index rows: {count}")

    if count == 0:
        raise ValueError(
            "CVE mart validation FAILED — mart_cve_threat_index is empty."
        )

    logging.info("CVE mart validation PASSED.")
    context["ti"].xcom_push(key="cve_mart_rows", value=count)


def log_pipeline_summary(**context):
    """
    Final task: Pull all XCom values and print a structured run summary
    to the Airflow task log. Visible in the Airflow UI under Task Logs.
    """
    ti = context["ti"]

    raw_uwf     = ti.xcom_pull(task_ids="uwf_pipeline.load_combined_parquet_to_duckdb", key="raw_uwf_count")
    cve_ingest  = ti.xcom_pull(task_ids="cve_pipeline.ingest_cve_to_clickhouse",         key="cve_ingested_count")
    uwf_nodes   = ti.xcom_pull(task_ids="validate_uwf_marts",                            key="uwf_nodes")
    uwf_edges   = ti.xcom_pull(task_ids="validate_uwf_marts",                            key="uwf_edges")
    uwf_gnn     = ti.xcom_pull(task_ids="validate_uwf_marts",                            key="uwf_gnn_rows")
    uwf_train   = ti.xcom_pull(task_ids="validate_uwf_marts",                            key="uwf_train_rows")
    uwf_test    = ti.xcom_pull(task_ids="validate_uwf_marts",                            key="uwf_test_rows")
    cve_mart    = ti.xcom_pull(task_ids="validate_cve_mart",                             key="cve_mart_rows")

    logging.info("=" * 65)
    logging.info("  CYBERSEC UNIFIED PIPELINE — RUN SUMMARY")
    logging.info("=" * 65)
    logging.info("  [UWF Network Logs — DuckDB]")
    logging.info(f"    Raw rows ingested      : {raw_uwf:,}")
    logging.info(f"    Unique IP nodes        : {uwf_nodes}  (expected 1,176)")
    logging.info(f"    Super-edges (mart)     : {uwf_edges}  (expected 2,183)")
    logging.info(f"    GNN-ready rows         : {uwf_gnn:,}")
    logging.info(f"    Train split            : {uwf_train:,}  (~80%)")
    logging.info(f"    Test split             : {uwf_test:,}   (~20%)")
    logging.info("  [CVE-MITRE — ClickHouse]")
    logging.info(f"    Records ingested       : {cve_ingest:,}")
    logging.info(f"    Mart aggregated rows   : {cve_mart:,}")
    logging.info("  Status: SUCCESS ✓")
    logging.info("=" * 65)


# =============================================================================
# ── DAG DEFINITION ────────────────────────────────────────────────────────────
# =============================================================================

with DAG(
    dag_id="cybersec_unified_pipeline",
    default_args=default_args,
    description=(
        "Dual ETL pipeline: UWF network logs (DuckDB + dbt) "
        "and CVE-MITRE (ClickHouse + dbt) for GraphRAG cybersecurity system."
    ),
    schedule_interval="@weekly",
    start_date=days_ago(1),
    catchup=False,
    tags=["cybersec", "uwf", "cve", "dbt", "duckdb", "clickhouse", "team3"],
) as dag:

    # =========================================================================
    # UWF PIPELINE TASK GROUP
    # =========================================================================
    with TaskGroup(group_id="uwf_pipeline") as uwf_group:

        t_scrape = PythonOperator(
            task_id="scrape_uwf_parquet",
            python_callable=scrape_uwf_parquet,
            doc_md="Scrape all UWF Zeek parquet files from datasets.uwf.edu",
        )

        t_combine = PythonOperator(
            task_id="combine_parquet_files",
            python_callable=combine_parquet_files,
            doc_md=(
                "Merge 50 individual period parquet files into one master file. "
                "Normalizes schema across dataset versions (23–27 cols)."
            ),
        )

        t_load = PythonOperator(
            task_id="load_combined_parquet_to_duckdb",
            python_callable=load_combined_parquet_to_duckdb,
            doc_md="Load combined_uwf_dataset.parquet into DuckDB network_logs table.",
        )

        t_validate_raw = PythonOperator(
            task_id="validate_uwf_raw",
            python_callable=validate_uwf_raw,
            doc_md="Validate row count (~27M) and required columns before dbt runs.",
        )

        # Cosmos: expands each dbt model as its own Airflow task
        # Models run in dependency order: stg → int → mart
        # Each model gets a _run task + _test task automatically
        uwf_dbt = DbtTaskGroup(
        group_id="dbt_uwf_models",
        project_config=ProjectConfig(
        dbt_project_path=DBT_PROJECT_PATH,
        manifest_path=DBT_PROJECT_PATH / "target" / "manifest.json",
        ),
        profile_config=uwf_profile_config,
        render_config=RenderConfig(load_method=LoadMode.DBT_MANIFEST),
        execution_config=ExecutionConfig(
        dbt_executable_path="/home/airflow/.local/bin/dbt",
        ),
        operator_args={"install_deps": True},
    )
            # Individual dbt tasks visible in Airflow:
            #   stg_network_logs_run   → stg_network_logs_test
            #   int_network_clean_run  → int_network_clean_test
            #   mart_node_mapping_run  → mart_node_mapping_test
            #   mart_super_edges_run   → mart_super_edges_test
            #   mart_gnn_ready_run     → mart_gnn_ready_test

        # UWF dependency chain
        t_scrape >> t_combine >> t_load >> t_validate_raw >> uwf_dbt

    # =========================================================================
    # CVE PIPELINE TASK GROUP
    # =========================================================================
    with TaskGroup(group_id="cve_pipeline") as cve_group:

        t_validate_src = PythonOperator(
            task_id="validate_cve_source",
            python_callable=validate_cve_source,
            doc_md="Validate CVE CSV file exists and has expected columns.",
        )

        t_ingest = PythonOperator(
            task_id="ingest_cve_to_clickhouse",
            python_callable=ingest_cve_to_clickhouse,
            doc_md=(
                "Batch load CVE-MITRE CSV into ClickHouse cve_mitre_master table. "
                "Batch size: 500 records. Idempotent via TRUNCATE + reload."
            ),
        )

        # Cosmos: expands each dbt model as its own Airflow task
        cve_dbt = DbtTaskGroup(
        group_id="dbt_cve_models",
        project_config=ProjectConfig(
        dbt_project_path=DBT_PROJECT_PATH,
        manifest_path=DBT_PROJECT_PATH / "target" / "manifest.json",
        ),
        profile_config=cve_profile_config,
        render_config=RenderConfig(load_method=LoadMode.DBT_MANIFEST),
        execution_config=ExecutionConfig(
        dbt_executable_path="/home/airflow/.local/bin/dbt",
        ),
        operator_args={"install_deps": True},
    )

        # CVE dependency chain
        t_validate_src >> t_ingest >> cve_dbt

    # =========================================================================
    # CONVERGENCE — runs after BOTH pipelines complete
    # =========================================================================

    t_val_uwf = PythonOperator(
        task_id="validate_uwf_marts",
        python_callable=validate_uwf_marts,
        doc_md=(
            "Validate DuckDB marts: 1,176 nodes, 2,183 edges, "
            "GNN-ready table with 80/20 train/test split."
        ),
    )

    t_val_cve = PythonOperator(
        task_id="validate_cve_mart",
        python_callable=validate_cve_mart,
        doc_md="Validate ClickHouse mart_cve_threat_index is populated.",
    )

    t_summary = PythonOperator(
        task_id="log_pipeline_summary",
        python_callable=log_pipeline_summary,
        doc_md="Print full run summary with row counts across both pipelines.",
    )

    # Both pipelines run in parallel, converge at validation, end at summary
    uwf_group >> t_val_uwf
    cve_group >> t_val_cve
    [t_val_uwf, t_val_cve] >> t_summary