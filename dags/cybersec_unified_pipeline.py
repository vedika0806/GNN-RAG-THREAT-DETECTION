# =============================================================================
# cybersec_unified_pipeline.py
#
# Unified Airflow DAG — GraphRAG Cybersecurity Threat Intelligence System
# Team 3 | DATA 298A
#
# UWF Network Logs → Web scrape → Combine Parquet → ClickHouse (analytics) → dbt
#
# Each dbt model appears as its own task in Airflow via astronomer-cosmos.
#
# Required pip packages (docker-compose _PIP_ADDITIONAL_REQUIREMENTS):
#   dbt-clickhouse astronomer-cosmos clickhouse-connect pandas beautifulsoup4
#   requests fastparquet pyarrow
# =============================================================================

from __future__ import annotations

import glob
import logging
import os
import time
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlparse

import clickhouse_connect
import pandas as pd
import requests
from bs4 import BeautifulSoup
from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.utils.dates import days_ago
from airflow.utils.task_group import TaskGroup

from cosmos import DbtTaskGroup, ExecutionConfig, ProfileConfig, ProjectConfig, RenderConfig
from cosmos.constants import LoadMode

# =============================================================================
# CONFIGURATION — override with env vars in production
# =============================================================================

UWF_BASE_URL = "https://datasets.uwf.edu/data/"
DATA_DIR = "/opt/Airflow/data"
UWF_RAW_DIR = f"{DATA_DIR}/UWF_Data"
PARQUET_FILE = f"{UWF_RAW_DIR}/combined_uwf_dataset.parquet"

# ClickHouse (hostname only, or full https URL — see _clickhouse_client)
CH_HOST = os.environ.get("CLICKHOUSE_HOST", "zkddrg7t39.us-west-2.aws.clickhouse.cloud")
CH_USER = os.environ.get("CLICKHOUSE_USER", "default")
CH_PASSWORD = os.environ.get("CLICKHOUSE_PASSWORD", "")

CH_ANALYTICS_DB = "analytics"
CH_RAW_TABLE = "network_logs"
CH_INSERT_BATCH_ROWS = 100_000

DBT_PROJECT_PATH = Path("/opt/Airflow/dbt")

UWF_NEW_COLS = ["label_technique", "label_cve", "label_binary", "vlan"]

NETWORK_LOGS_COLUMNS = [
    "resp_pkts",
    "service",
    "orig_ip_bytes",
    "local_resp",
    "missed_bytes",
    "proto",
    "duration",
    "conn_state",
    "dest_ip_zeek",
    "orig_pkts",
    "community_id",
    "resp_ip_bytes",
    "dest_port_zeek",
    "orig_bytes",
    "local_orig",
    "datetime",
    "history",
    "resp_bytes",
    "uid",
    "src_port_zeek",
    "ts",
    "src_ip_zeek",
    "label_tactic",
    "source_period",
    "label_technique",
    "label_cve",
    "label_binary",
    "vlan",
]

clickhouse_profile_config = ProfileConfig(
    profile_name="cybersec_clickhouse",
    target_name="prod",
    profiles_yml_filepath=DBT_PROJECT_PATH / "profiles.yml",
)

default_args = {
    "owner": "team3",
    "retries": 2,
    "retry_delay": timedelta(minutes=3),
    "email_on_failure": False,
}


def _clickhouse_client():
    """Build clickhouse_connect client; CH_HOST may be hostname or https://host:8443."""
    raw = CH_HOST.strip()
    if raw.startswith("http://") or raw.startswith("https://"):
        parsed = urlparse(raw)
        host = parsed.hostname
        port = parsed.port or 8443
        if not host:
            raise ValueError(f"Could not parse hostname from CLICKHOUSE_HOST / CH_HOST: {raw!r}")
    else:
        host = raw.split("/")[0].split(":")[0]
        port = 8443 if "clickhouse.cloud" in host else 8123

    return clickhouse_connect.get_client(
        host=host,
        port=port,
        username=CH_USER,
        password=CH_PASSWORD,
        secure=port == 8443,
    )


def _add_missing_network_log_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Ensure all columns exist (combine step may omit rare Zeek fields in some periods)."""
    df = df.copy()
    for col in NETWORK_LOGS_COLUMNS:
        if col not in df.columns:
            if col in ("local_resp", "local_orig"):
                df[col] = False
            elif col in (
                "resp_pkts",
                "orig_ip_bytes",
                "missed_bytes",
                "orig_pkts",
                "resp_ip_bytes",
                "orig_bytes",
                "resp_bytes",
                "dest_port_zeek",
                "src_port_zeek",
            ):
                df[col] = 0
            elif col in ("duration", "ts"):
                df[col] = 0.0
            elif col == "datetime":
                df[col] = pd.NaT
            else:
                df[col] = ""
            logging.warning("Parquet missing column %r — filled with default.", col)
    return df


def _datetime_series_for_clickhouse(s: pd.Series) -> pd.Series:
    """Naive datetimes for DateTime64(3); NaT → epoch; strip timezone if present."""
    dt = pd.to_datetime(s, errors="coerce", utc=True)
    if pd.api.types.is_datetime64_any_dtype(dt) and getattr(dt.dtype, "tz", None) is not None:
        dt = dt.dt.tz_convert("UTC").dt.tz_localize(None)
    nat = dt.isna()
    if nat.any():
        logging.warning("datetime has %s NaT values; using 1970-01-01 00:00:00", int(nat.sum()))
        dt = dt.fillna(pd.Timestamp("1970-01-01 00:00:00"))
    return dt


def _ensure_network_logs_dtypes(df: pd.DataFrame) -> pd.DataFrame:
    """Align pandas dtypes with ClickHouse table for insert_df."""
    df = _add_missing_network_log_columns(df)
    bool_cols = ["local_resp", "local_orig"]
    for c in bool_cols:
        if c in df.columns:
            # UInt8 matches ClickHouse table (avoids Bool + insert_df edge cases)
            df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0).clip(0, 1).astype("uint8")
    int64_cols = [
        "resp_pkts",
        "orig_ip_bytes",
        "missed_bytes",
        "orig_pkts",
        "resp_ip_bytes",
        "orig_bytes",
        "resp_bytes",
    ]
    for c in int64_cols:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0).astype("int64")
    int32_cols = ["dest_port_zeek", "src_port_zeek"]
    for c in int32_cols:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0).astype("int32")
    if "duration" in df.columns:
        df["duration"] = pd.to_numeric(df["duration"], errors="coerce").fillna(0.0)
    if "ts" in df.columns:
        df["ts"] = pd.to_numeric(df["ts"], errors="coerce").fillna(0.0)
    if "datetime" in df.columns:
        df["datetime"] = _datetime_series_for_clickhouse(df["datetime"])
    str_cols = [
        "service",
        "proto",
        "conn_state",
        "dest_ip_zeek",
        "community_id",
        "history",
        "uid",
        "src_ip_zeek",
        "label_tactic",
        "source_period",
        "label_technique",
        "label_cve",
        "label_binary",
        "vlan",
    ]
    for c in str_cols:
        if c in df.columns:
            df[c] = df[c].astype(str).replace("nan", "")
    return df[NETWORK_LOGS_COLUMNS]


# =============================================================================
# UWF PIPELINE
# =============================================================================


def scrape_uwf_parquet(**context):
    """
    Scrape parquet files from the UWF dataset portal (idempotent for existing files).
    """
    os.makedirs(UWF_RAW_DIR, exist_ok=True)
    downloaded = []

    def scrape(url, local_path):
        time.sleep(1)
        try:
            response = requests.get(url, timeout=10)
            soup = BeautifulSoup(response.text, "html.parser")
        except Exception as e:
            logging.error(f"Failed to access {url}: {e}")
            return

        for link in soup.find_all("a"):
            href = link.get("href", "")

            if href in ["../", "SUCCESS", "_SUCCESS"] or "?" in href:
                continue

            full_url = url + href

            if href.endswith("/"):
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
    Merge period parquet files into combined_uwf_dataset.parquet; normalize columns.
    Uses a canonical pyarrow schema so files with varying dtypes / column order combine cleanly.
    """
    import pyarrow as pa
    import pyarrow.parquet as pq

    # Canonical schema — every file is cast to this before writing.
    CANONICAL_SCHEMA = pa.schema([
        ("community_id",    pa.string()),
        ("conn_state",      pa.string()),
        ("duration",        pa.float64()),
        ("history",         pa.string()),
        ("src_ip_zeek",     pa.string()),
        ("src_port_zeek",   pa.int64()),
        ("dest_ip_zeek",    pa.string()),
        ("dest_port_zeek",  pa.int64()),
        ("local_orig",      pa.bool_()),
        ("local_resp",      pa.bool_()),
        ("missed_bytes",    pa.int64()),
        ("orig_bytes",      pa.float64()),
        ("orig_ip_bytes",   pa.int64()),
        ("orig_pkts",       pa.int64()),
        ("proto",           pa.string()),
        ("resp_bytes",      pa.float64()),
        ("resp_ip_bytes",   pa.int64()),
        ("resp_pkts",       pa.int64()),
        ("service",         pa.string()),
        ("ts",              pa.float64()),
        ("uid",             pa.string()),
        ("datetime",        pa.timestamp("ns")),
        ("vlan",            pa.string()),
        ("label_tactic",    pa.string()),
        ("label_technique", pa.string()),
        ("label_binary",    pa.string()),
        ("label_cve",       pa.string()),
        ("source_period",   pa.string()),
    ])

    def _cast_column(col, target_type):
        """Cast a pyarrow column to target_type, handling nulls and type mismatches."""
        if col.type.equals(target_type):
            return col
        if pa.types.is_null(col.type):
            return pa.nulls(len(col), type=target_type)
        return col.cast(target_type, safe=False)

    search_pattern = os.path.join(UWF_RAW_DIR, "**", "parquet", "**", "part-*.parquet")
    files = glob.glob(search_pattern, recursive=True)

    if not files:
        raise FileNotFoundError(
            f"No parquet files found under {UWF_RAW_DIR}. "
            "Check that scrape_uwf_parquet ran successfully."
        )

    logging.info(f"Found {len(files)} parquet files to combine.")

    if os.path.exists(PARQUET_FILE):
        os.remove(PARQUET_FILE)
        logging.info("Removed existing combined_uwf_dataset.parquet")

    writer = pq.ParquetWriter(PARQUET_FILE, CANONICAL_SCHEMA, compression="snappy")
    files_written = 0

    for i, file_path in enumerate(files):
        try:
            table = pq.read_table(file_path)
            nrows = table.num_rows

            folder_name = os.path.basename(os.path.dirname(file_path))

            # Add source_period column
            table = table.append_column(
                "source_period", pa.array([folder_name] * nrows, type=pa.string())
            )

            # Add missing UWF_NEW_COLS with "unknown"
            for col in UWF_NEW_COLS:
                if col not in table.column_names:
                    table = table.append_column(
                        col, pa.array(["unknown"] * nrows, type=pa.string())
                    )

            # Build canonical columns list, casting types as needed
            canonical_columns = []
            for field in CANONICAL_SCHEMA:
                if field.name in table.column_names:
                    canonical_columns.append(
                        _cast_column(table.column(field.name), field.type)
                    )
                else:
                    canonical_columns.append(pa.nulls(nrows, type=field.type))

            out = pa.table(
                canonical_columns,
                names=[f.name for f in CANONICAL_SCHEMA],
            )
            writer.write_table(out)
            files_written += 1

            # Free memory immediately
            del table, out, canonical_columns

            if i % 10 == 0:
                logging.info(f"Progress: {i}/{len(files)} files combined.")

        except Exception as e:
            logging.error(f"Error processing {file_path}: {e}")

    writer.close()

    logging.info(f"Combined parquet saved to: {PARQUET_FILE} ({files_written}/{len(files)} files)")
    context["ti"].xcom_push(key="files_combined", value=files_written)


def load_combined_parquet_to_clickhouse(**context):
    """
    Load combined_uwf_dataset.parquet into ClickHouse analytics.network_logs (batched).
    """
    if not os.path.exists(PARQUET_FILE):
        raise FileNotFoundError(
            f"Combined parquet not found at {PARQUET_FILE}. "
            "Ensure combine_parquet_files ran successfully."
        )

    client = _clickhouse_client()
    fqtn = f"{CH_ANALYTICS_DB}.{CH_RAW_TABLE}"

    client.command(f"CREATE DATABASE IF NOT EXISTS {CH_ANALYTICS_DB}")

    client.command(f"DROP TABLE IF EXISTS {fqtn}")

    # Log parquet schema once (helps debug column / type mismatches)
    try:
        import pyarrow.parquet as pq_dbg

        pf = pq_dbg.ParquetFile(PARQUET_FILE)
        logging.info(
            "Parquet row_groups=%s columns=%s",
            pf.num_row_groups,
            pf.schema_arrow.names,
        )
    except Exception as e:
        logging.info("Could not introspect parquet schema: %s", e)

    client.command(f"""
        CREATE TABLE {fqtn} (
            resp_pkts        Int64,
            service          String,
            orig_ip_bytes    Int64,
            local_resp       UInt8,
            missed_bytes     Int64,
            proto            String,
            duration         Float64,
            conn_state       String,
            dest_ip_zeek     String,
            orig_pkts        Int64,
            community_id     String,
            resp_ip_bytes    Int64,
            dest_port_zeek   Int32,
            orig_bytes       Int64,
            local_orig       UInt8,
            datetime         DateTime64(3),
            history          String,
            resp_bytes       Int64,
            uid              String,
            src_port_zeek    Int32,
            ts               Float64,
            src_ip_zeek      String,
            label_tactic     String,
            source_period    String,
            label_technique  String,
            label_cve        String,
            label_binary     String,
            vlan             String
        )
        ENGINE = MergeTree()
        ORDER BY (src_ip_zeek, dest_ip_zeek, datetime)
    """)

    total = 0
    try:
        import pyarrow.parquet as pq

        reader = pq.ParquetFile(PARQUET_FILE)
        for rg in range(reader.num_row_groups):
            try:
                tbl = reader.read_row_group(rg)
                df = tbl.to_pandas()
            except Exception as e:
                logging.exception("read_row_group(%s) failed: %s", rg, e)
                raise RuntimeError(
                    f"Failed reading parquet row group {rg}/{reader.num_row_groups}. "
                    "If this file was built with fastparquet append=True, try rebuilding "
                    "combined_uwf_dataset.parquet or use a single-engine read path."
                ) from e
            df = _ensure_network_logs_dtypes(df)
            for start in range(0, len(df), CH_INSERT_BATCH_ROWS):
                chunk = df.iloc[start : start + CH_INSERT_BATCH_ROWS]
                try:
                    client.insert_df(fqtn, chunk)
                except Exception as e:
                    logging.error(
                        "insert_df failed row_group=%s batch_start=%s dtypes=%s",
                        rg,
                        start,
                        chunk.dtypes.to_dict(),
                    )
                    raise
                total += len(chunk)
            logging.info(f"Loaded row group {rg + 1}/{reader.num_row_groups} ({total:,} rows so far)")
    except ImportError:
        logging.warning("pyarrow not installed; loading full parquet into memory.")
        df = _ensure_network_logs_dtypes(pd.read_parquet(PARQUET_FILE, engine="fastparquet"))
        for start in range(0, len(df), CH_INSERT_BATCH_ROWS):
            chunk = df.iloc[start : start + CH_INSERT_BATCH_ROWS]
            client.insert_df(fqtn, chunk)
            total += len(chunk)

    logging.info(f"Loaded {total:,} rows into {fqtn}.")
    context["ti"].xcom_push(key="raw_uwf_count", value=total)


def validate_uwf_raw(**context):
    """Validate analytics.network_logs row count and required columns."""
    client = _clickhouse_client()
    fqtn = f"{CH_ANALYTICS_DB}.{CH_RAW_TABLE}"

    count = client.query(f"SELECT count() FROM {fqtn}").result_rows[0][0]
    logging.info(f"Raw row count: {count:,}")

    rows = client.query(
        f"""
        SELECT name FROM system.columns
        WHERE database = '{CH_ANALYTICS_DB}' AND table = '{CH_RAW_TABLE}'
        """
    ).result_rows
    cols = {r[0] for r in rows}

    required = {
        "src_ip_zeek",
        "dest_ip_zeek",
        "proto",
        "label_tactic",
        "label_binary",
        "source_period",
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


def validate_uwf_marts(**context):
    """
    Validate dbt marts in ClickHouse analytics: node/edge counts and GNN split.
    """
    client = _clickhouse_client()
    db = CH_ANALYTICS_DB

    nodes = client.query(f"SELECT count() FROM {db}.mart_node_mapping").result_rows[0][0]
    edges = client.query(f"SELECT count() FROM {db}.mart_super_edges").result_rows[0][0]
    gnn = client.query(f"SELECT count() FROM {db}.mart_gnn_ready").result_rows[0][0]
    train = client.query(
        f"SELECT count() FROM {db}.mart_gnn_ready WHERE split_mask = 'train'"
    ).result_rows[0][0]
    test = client.query(
        f"SELECT count() FROM {db}.mart_gnn_ready WHERE split_mask = 'test'"
    ).result_rows[0][0]

    logging.info(
        f"UWF marts — nodes: {nodes}, edges: {edges}, "
        f"gnn_ready: {gnn} (train: {train}, test: {test})"
    )

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


def log_pipeline_summary(**context):
    ti = context["ti"]

    raw_uwf = ti.xcom_pull(
        task_ids="uwf_pipeline.load_combined_parquet_to_clickhouse", key="raw_uwf_count"
    )
    uwf_nodes = ti.xcom_pull(task_ids="validate_uwf_marts", key="uwf_nodes")
    uwf_edges = ti.xcom_pull(task_ids="validate_uwf_marts", key="uwf_edges")
    uwf_gnn = ti.xcom_pull(task_ids="validate_uwf_marts", key="uwf_gnn_rows")
    uwf_train = ti.xcom_pull(task_ids="validate_uwf_marts", key="uwf_train_rows")
    uwf_test = ti.xcom_pull(task_ids="validate_uwf_marts", key="uwf_test_rows")

    logging.info("=" * 65)
    logging.info("  CYBERSEC UNIFIED PIPELINE — RUN SUMMARY")
    logging.info("=" * 65)
    logging.info(f"  [UWF Network Logs — ClickHouse `{CH_ANALYTICS_DB}`]")
    logging.info(f"    Raw rows ingested      : {raw_uwf:,}")
    logging.info(f"    Unique IP nodes        : {uwf_nodes}  (expected 1,176)")
    logging.info(f"    Super-edges (mart)     : {uwf_edges}  (expected 2,183)")
    logging.info(f"    GNN-ready rows         : {uwf_gnn:,}")
    logging.info(f"    Train split            : {uwf_train:,}  (~80%)")
    logging.info(f"    Test split             : {uwf_test:,}   (~20%)")
    logging.info("  Status: SUCCESS ✓")
    logging.info("=" * 65)


# =============================================================================
# DAG
# =============================================================================

with DAG(
    dag_id="cybersec_unified_pipeline",
    default_args=default_args,
    description=(
        "UWF network logs: scrape → parquet → ClickHouse analytics → dbt for GraphRAG."
    ),
    schedule_interval="@weekly",
    start_date=days_ago(1),
    catchup=False,
    tags=["cybersec", "uwf", "dbt", "clickhouse", "team3"],
) as dag:

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
                "Merge period parquet files into one master file. "
                "Normalizes schema across dataset versions (23–27 cols)."
            ),
        )

        t_load = PythonOperator(
            task_id="load_combined_parquet_to_clickhouse",
            python_callable=load_combined_parquet_to_clickhouse,
            doc_md="Load combined parquet into ClickHouse analytics.network_logs.",
        )

        t_validate_raw = PythonOperator(
            task_id="validate_uwf_raw",
            python_callable=validate_uwf_raw,
            doc_md="Validate row count (~27M) and required columns before dbt runs.",
        )

        uwf_dbt = DbtTaskGroup(
            group_id="dbt_uwf_models",
            project_config=ProjectConfig(
                dbt_project_path=DBT_PROJECT_PATH,
                manifest_path=DBT_PROJECT_PATH / "target" / "manifest.json",
            ),
            profile_config=clickhouse_profile_config,
            render_config=RenderConfig(load_method=LoadMode.DBT_MANIFEST),
            execution_config=ExecutionConfig(
                dbt_executable_path="/home/airflow/.local/bin/dbt",
            ),
            operator_args={"install_deps": True},
        )

        t_scrape >> t_combine >> t_load >> t_validate_raw >> uwf_dbt

    t_val_uwf = PythonOperator(
        task_id="validate_uwf_marts",
        python_callable=validate_uwf_marts,
        doc_md=(
            "Validate ClickHouse analytics marts: 1,176 nodes, 2,183 edges, "
            "GNN-ready table with 80/20 train/test split."
        ),
    )

    t_summary = PythonOperator(
        task_id="log_pipeline_summary",
        python_callable=log_pipeline_summary,
        doc_md="Print run summary with row counts.",
    )

    uwf_group >> t_val_uwf >> t_summary
