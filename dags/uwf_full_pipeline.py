"""
Airflow DAG: uwf_full_pipeline

Single end-to-end pipeline triggered once daily:
  Bronze ingestion → Silver dbt → Gold dbt → dbt tests → PyG export → Monitoring

Replaces the two-DAG setup (uwf_bronze_ingestion + uwf_silver_gold_transform).
New files from the UWF HTTP server are discovered, downloaded, staged to Snowflake,
and the full transformation + export chain runs automatically afterward.

Monitoring checks (final task):
  - Bronze: row count > 0
  - Silver: null rate on key columns < 1%
  - Gold: node count == 1176, edge count == 2183, attack edge % in [5%, 60%]
  - PyG: tensor shapes, attack label present

Schedule: daily at 02:00 UTC
"""

from __future__ import annotations

import hashlib
import os
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Generator

import requests
from bs4 import BeautifulSoup

from airflow import DAG
from airflow.decorators import task
from airflow.operators.bash import BashOperator
from airflow.operators.empty import EmptyOperator
from airflow.providers.snowflake.hooks.snowflake import SnowflakeHook
from airflow.providers.snowflake.operators.snowflake import SnowflakeOperator
from airflow.utils.trigger_rule import TriggerRule

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
UWF_BASE_URL       = "https://datasets.uwf.edu/data/"
SNOWFLAKE_CONN_ID  = "snowflake_default"
SNOWFLAKE_DATABASE = os.getenv("SNOWFLAKE_DATABASE", "USER_DB_LEMMING")
DBT_PROJECT_DIR    = os.getenv("DBT_PROJECT_DIR", "/opt/airflow/transform")
DBT_PROFILES_DIR   = os.getenv("DBT_PROFILES_DIR", "/opt/airflow/transform")
LOCAL_STAGING_DIR  = Path("/tmp/uwf_staging")
OUTPUT_DIR         = Path(os.getenv("GNN_OUTPUT_DIR", "/opt/airflow/gnn_artifacts"))

DEFAULT_ARGS = {
    "owner": "data-engineering",
    "retries": 2,
    "retry_delay": timedelta(minutes=5),
    "retry_exponential_backoff": True,
    "email_on_failure": False,
    "execution_timeout": timedelta(hours=6),
}

_DBT_ENV = {
    "SNOWFLAKE_ACCOUNT":   "{{ conn.snowflake_default.host }}",
    "SNOWFLAKE_USER":      "{{ conn.snowflake_default.login }}",
    "SNOWFLAKE_PASSWORD":  "{{ conn.snowflake_default.password }}",
    "SNOWFLAKE_DATABASE":  SNOWFLAKE_DATABASE,
    "SNOWFLAKE_ROLE":      os.getenv("SNOWFLAKE_ROLE", "TRAINING_ROLE"),
    "SNOWFLAKE_WAREHOUSE": os.getenv("SNOWFLAKE_WAREHOUSE", "LEMMING_QUERY_WH"),
    **os.environ,
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _iter_parquet_urls(base_url: str, _depth: int = 0) -> Generator[tuple[str, str], None, None]:
    if _depth > 4:
        return
    time.sleep(0.5)
    try:
        resp = requests.get(base_url, timeout=15)
        resp.raise_for_status()
    except requests.RequestException as exc:
        print(f"[WARN] Could not fetch {base_url}: {exc}")
        return
    soup = BeautifulSoup(resp.text, "html.parser")
    for link in soup.find_all("a"):
        href = link.get("href", "")
        if href in ("../", "") or "?" in href:
            continue
        full_url = base_url.rstrip("/") + "/" + href.rstrip("/")
        if href.endswith("/"):
            if "csv" in href.lower() or "metric" in href.lower():
                continue
            yield from _iter_parquet_urls(full_url + "/", _depth + 1)
        elif href.startswith("part-") and href.endswith(".parquet"):
            parts = base_url.rstrip("/").split("/")
            source_period = parts[-1] if parts[-1] != "parquet" else parts[-2]
            yield full_url, source_period


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# DAG
# ---------------------------------------------------------------------------
with DAG(
    dag_id="uwf_full_pipeline",
    description="End-to-end pipeline: Bronze ingestion → Silver+Gold dbt → PyG export → Monitoring.",
    schedule_interval="0 2 * * *",
    start_date=datetime(2026, 1, 1),
    catchup=False,
    default_args=DEFAULT_ARGS,
    tags=["bronze", "silver", "gold", "gnn", "monitoring"],
    max_active_runs=1,
) as dag:

    # ------------------------------------------------------------------ #
    # Stage 0: Ensure Snowflake control tables exist                       #
    # ------------------------------------------------------------------ #
    ensure_tables = SnowflakeOperator(
        task_id="ensure_tables",
        snowflake_conn_id=SNOWFLAKE_CONN_ID,
        sql=f"""
            CREATE SCHEMA IF NOT EXISTS {SNOWFLAKE_DATABASE}.RAW;
            CREATE SCHEMA IF NOT EXISTS {SNOWFLAKE_DATABASE}.SILVER;
            CREATE SCHEMA IF NOT EXISTS {SNOWFLAKE_DATABASE}.GOLD;

            CREATE TABLE IF NOT EXISTS {SNOWFLAKE_DATABASE}.RAW.INGESTION_LOG (
                source_period   VARCHAR,
                filename        VARCHAR,
                file_sha256     VARCHAR,
                row_count       BIGINT,
                ingested_at     TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
                PRIMARY KEY (source_period, filename)
            );

            CREATE TABLE IF NOT EXISTS {SNOWFLAKE_DATABASE}.RAW.NETWORK_LOGS_RAW (
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
                datetime        TIMESTAMP_NTZ,
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
                vlan            VARCHAR,
                _ingested_at    TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
                _source_file    VARCHAR
            );
        """,
    )

    # ------------------------------------------------------------------ #
    # Stage 1: Discover new parquet files from UWF HTTP server             #
    # ------------------------------------------------------------------ #
    @task()
    def discover_new_files() -> list[dict]:
        hook = SnowflakeHook(snowflake_conn_id=SNOWFLAKE_CONN_ID)
        already_loaded: set[tuple[str, str]] = set()
        for row in hook.get_records(
            f"SELECT source_period, filename FROM {SNOWFLAKE_DATABASE}.RAW.INGESTION_LOG"
        ):
            already_loaded.add((row[0], row[1]))

        new_files = []
        for url, source_period in _iter_parquet_urls(UWF_BASE_URL):
            filename = url.split("/")[-1]
            if (source_period, filename) not in already_loaded:
                new_files.append({"url": url, "source_period": source_period, "filename": filename})

        print(f"[INFO] {len(new_files)} new files to ingest.")
        return new_files

    # ------------------------------------------------------------------ #
    # Stage 2: Download → internal stage → COPY INTO (parallel per file)  #
    # ------------------------------------------------------------------ #
    @task()
    def ingest_file(file_info: dict) -> dict:
        import pandas as pd

        url           = file_info["url"]
        source_period = file_info["source_period"]
        filename      = file_info["filename"]

        LOCAL_STAGING_DIR.mkdir(parents=True, exist_ok=True)
        local_path = LOCAL_STAGING_DIR / filename

        print(f"[INFO] Downloading {filename} ({source_period})")
        with requests.get(url, stream=True, timeout=120) as r:
            r.raise_for_status()
            with open(local_path, "wb") as f:
                for chunk in r.iter_content(chunk_size=65536):
                    f.write(chunk)

        sha = _sha256(local_path)

        df = pd.read_parquet(local_path, engine="fastparquet")
        df["source_period"] = source_period
        df["_source_file"]  = filename
        for col in {"label_technique", "label_cve", "label_binary", "vlan"}:
            if col not in df.columns:
                df[col] = "unknown"
            else:
                df[col] = df[col].astype(str).replace({"nan": "unknown", "NaN": "unknown", "None": "unknown", "none": "unknown"})

        row_count = len(df)
        normalized_path = LOCAL_STAGING_DIR / f"norm_{filename}"
        df.to_parquet(normalized_path, engine="fastparquet", compression="snappy")

        hook       = SnowflakeHook(snowflake_conn_id=SNOWFLAKE_CONN_ID)
        stage_name = f"{SNOWFLAKE_DATABASE}.RAW.%NETWORK_LOGS_RAW"

        with hook.get_conn() as conn:
            cs = conn.cursor()
            try:
                cs.execute(
                    f"PUT file://{normalized_path} @{stage_name} "
                    f"AUTO_COMPRESS=FALSE OVERWRITE=TRUE"
                )
                copy_result = cs.execute(f"""
                    COPY INTO {SNOWFLAKE_DATABASE}.RAW.NETWORK_LOGS_RAW
                    FROM @{stage_name}/{normalized_path.name}
                    FILE_FORMAT = (TYPE='PARQUET' SNAPPY_COMPRESSION=TRUE)
                    MATCH_BY_COLUMN_NAME = CASE_INSENSITIVE
                    ON_ERROR = 'ABORT_STATEMENT'
                    PURGE = TRUE
                """)
                copy_row = copy_result.fetchone()
                rows_loaded = copy_row[3] if copy_row else 0  # col 3 = rows_loaded
                if rows_loaded == 0:
                    raise RuntimeError(
                        f"COPY INTO loaded 0 rows for {filename}. "
                        f"COPY result: {copy_row}"
                    )
                cs.execute(
                    f"INSERT INTO {SNOWFLAKE_DATABASE}.RAW.INGESTION_LOG "
                    f"(source_period, filename, file_sha256, row_count) "
                    f"VALUES (%s, %s, %s, %s)",
                    (source_period, filename, sha, row_count),
                )
            finally:
                cs.close()

        local_path.unlink(missing_ok=True)
        normalized_path.unlink(missing_ok=True)
        print(f"[INFO] Loaded {row_count:,} rows from {filename}")
        return {"filename": filename, "row_count": row_count}

    # ------------------------------------------------------------------ #
    # Stage 2 gate: summarize Bronze results before triggering transforms  #
    # ------------------------------------------------------------------ #
    @task()
    def summarize_bronze(results: list[dict]) -> dict:
        total_rows  = sum(r.get("row_count", 0) for r in results if r)
        total_files = len([r for r in results if r])
        print(f"[INFO] Bronze complete — {total_files} files, {total_rows:,} rows loaded.")
        return {"files_loaded": total_files, "rows_loaded": total_rows}

    # ------------------------------------------------------------------ #
    # Stage 3: dbt Silver                                                  #
    # ------------------------------------------------------------------ #
    dbt_silver = BashOperator(
        task_id="dbt_silver",
        bash_command=(
            f"cd {DBT_PROJECT_DIR} && "
            f"dbt run --profiles-dir {DBT_PROFILES_DIR} --select +tag:silver --target dev"
        ),
        env=_DBT_ENV,
        trigger_rule=TriggerRule.ALL_DONE,
    )

    # ------------------------------------------------------------------ #
    # Stage 4: dbt Gold                                                    #
    # ------------------------------------------------------------------ #
    dbt_gold = BashOperator(
        task_id="dbt_gold",
        bash_command=(
            f"cd {DBT_PROJECT_DIR} && "
            f"dbt run --profiles-dir {DBT_PROFILES_DIR} --select tag:gold --target dev"
        ),
        env=_DBT_ENV,
    )

    # ------------------------------------------------------------------ #
    # Stage 5: dbt test — schema + singular quality tests                  #
    # ------------------------------------------------------------------ #
    dbt_test = BashOperator(
        task_id="dbt_test",
        bash_command=(
            f"cd {DBT_PROJECT_DIR} && "
            f"dbt test --profiles-dir {DBT_PROFILES_DIR} --target dev"
        ),
        env=_DBT_ENV,
    )

    # ------------------------------------------------------------------ #
    # Stage 6: Export Gold → PyTorch Geometric .pt file                   #
    # ------------------------------------------------------------------ #
    @task()
    def export_pyg(run_date: str) -> str:
        import torch
        from torch_geometric.data import Data
        from airflow.providers.snowflake.hooks.snowflake import SnowflakeHook

        hook = SnowflakeHook(snowflake_conn_id=SNOWFLAKE_CONN_ID)
        db   = SNOWFLAKE_DATABASE

        node_feature_cols = [
            "log_out_degree", "log_in_degree",
            "log_flows_out", "log_flows_in",
            "avg_log_duration_out", "avg_log_orig_bytes_out", "avg_log_resp_bytes_in",
            "attack_ratio_out", "attack_ratio_in",
            "proto_tcp_ratio_out", "proto_udp_ratio_out",
            "srv_http_ratio_out", "srv_dns_ratio_out",
            "conn_sf_ratio_out", "is_local",
        ]
        df_nodes = hook.get_pandas_df(
            f"SELECT {', '.join(node_feature_cols)} "
            f"FROM {db}.GOLD.GNN_NODE_FEATURES ORDER BY node_id"
        )
        df_nodes.columns = df_nodes.columns.str.lower()  # Snowflake returns UPPERCASE
        x = torch.tensor(df_nodes[node_feature_cols].values, dtype=torch.float)

        edge_feature_cols = [
            "edge_weight", "avg_log_duration", "avg_log_orig_bytes", "avg_log_resp_bytes",
            "log_total_tcp", "log_total_udp", "log_total_http", "log_total_dns",
            "conn_s0_ratio", "attack_flow_ratio",
        ]
        df_edges = hook.get_pandas_df(
            f"SELECT source_idx, target_idx, "
            f"{', '.join(edge_feature_cols)}, is_attack_edge, split "
            f"FROM {db}.GOLD.GNN_EDGE_ATTR ORDER BY source_idx, target_idx"
        )
        df_edges.columns = df_edges.columns.str.lower()  # Snowflake returns UPPERCASE

        edge_index = torch.tensor(df_edges[["source_idx", "target_idx"]].values.T, dtype=torch.long)
        edge_attr  = torch.tensor(df_edges[edge_feature_cols].values, dtype=torch.float)
        y          = torch.tensor(df_edges["is_attack_edge"].values, dtype=torch.long)

        train_mask = torch.tensor(df_edges["split"] == "train", dtype=torch.bool)
        val_mask   = torch.tensor(df_edges["split"] == "val",   dtype=torch.bool)
        test_mask  = torch.tensor(df_edges["split"] == "test",  dtype=torch.bool)

        n_normal   = int((y == 0).sum())
        n_attack   = int((y == 1).sum())
        pos_weight = torch.tensor([n_normal / max(n_attack, 1)], dtype=torch.float)

        data = Data(
            x=x, edge_index=edge_index, edge_attr=edge_attr, y=y,
            train_mask=train_mask, val_mask=val_mask, test_mask=test_mask,
        )
        data.pos_weight = pos_weight

        assert x.shape[0] == 1176,  f"Expected 1176 nodes, got {x.shape[0]}"
        assert x.shape[1] == 15,    f"Expected 15 node features, got {x.shape[1]}"
        assert edge_index.shape[1] > 0, "No edges exported — Gold edge table is empty."
        assert edge_attr.shape[1] == 10, f"Expected 10 edge features, got {edge_attr.shape[1]}"
        assert edge_index.max().item() < x.shape[0], \
            f"edge_index references node ID {edge_index.max().item()} but only {x.shape[0]} nodes exist"
        assert y.sum() > 0,         "No attack edges — labeling pipeline broken."

        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        output_path = OUTPUT_DIR / f"uwf_gnn_data_{run_date}.pt"
        torch.save(data, output_path)

        print(f"[INFO] Nodes: {data.num_nodes} | Edges: {data.num_edges}")
        print(f"[INFO] Attack: {n_attack} | Normal: {n_normal} | pos_weight: {pos_weight.item():.2f}")
        print(f"[INFO] Split — train: {train_mask.sum()} | val: {val_mask.sum()} | test: {test_mask.sum()}")
        print(f"[INFO] Saved → {output_path}")
        return str(output_path)

    # ------------------------------------------------------------------ #
    # Stage 7: Monitoring — data quality checks across all layers          #
    # ------------------------------------------------------------------ #
    @task()
    def monitor_pipeline(pyg_path: str) -> dict:
        import torch

        hook = SnowflakeHook(snowflake_conn_id=SNOWFLAKE_CONN_ID)
        db   = SNOWFLAKE_DATABASE
        failures: list[str] = []

        # --- Bronze ---
        bronze_rows = hook.get_first(
            f"SELECT COUNT(*) FROM {db}.RAW.NETWORK_LOGS_RAW"
        )[0]
        print(f"[MONITOR] Bronze rows: {bronze_rows:,}")
        if bronze_rows == 0:
            failures.append("Bronze: NETWORK_LOGS_RAW is empty")

        # --- Silver ---
        silver_stats = hook.get_first(f"""
            SELECT
                COUNT(*)                                                      AS total_rows,
                SUM(CASE WHEN src_ip_zeek  IS NULL THEN 1 ELSE 0 END)        AS null_src,
                SUM(CASE WHEN dest_ip_zeek IS NULL THEN 1 ELSE 0 END)        AS null_dest,
                SUM(CASE WHEN final_target IS NULL THEN 1 ELSE 0 END)        AS null_label,
                SUM(CASE WHEN final_target = 'Attack' THEN 1 ELSE 0 END)     AS attack_rows
            FROM {db}.SILVER.NETWORK_LOGS_CLEAN
        """)
        total, null_src, null_dest, null_label, attack_rows = silver_stats
        print(f"[MONITOR] Silver rows: {total:,} | attack: {attack_rows:,} ({100*attack_rows/max(total,1):.1f}%)")

        null_threshold = 0.01  # 1%
        for col, null_count in [("src_ip_zeek", null_src), ("dest_ip_zeek", null_dest), ("final_target", null_label)]:
            null_rate = null_count / max(total, 1)
            if null_rate > null_threshold:
                failures.append(f"Silver: {col} null rate {null_rate:.1%} exceeds 1% threshold")

        # --- Gold ---
        node_count = hook.get_first(
            f"SELECT COUNT(*) FROM {db}.GOLD.GNN_NODE_FEATURES"
        )[0]
        edge_stats = hook.get_first(f"""
            SELECT
                COUNT(*)                                                     AS edge_count,
                SUM(CASE WHEN is_attack_edge = 1 THEN 1 ELSE 0 END)         AS attack_edges
            FROM {db}.GOLD.GNN_EDGE_ATTR
        """)
        edge_count, attack_edges = edge_stats
        attack_pct = attack_edges / max(edge_count, 1)

        print(f"[MONITOR] Gold nodes: {node_count} | edges: {edge_count} | attack edges: {attack_pct:.1%}")

        if node_count != 1176:
            failures.append(f"Gold: expected 1176 nodes, got {node_count}")
        if edge_count < 2183:
            failures.append(f"Gold: expected >= 2183 edges, got {edge_count}")
        if not (0.05 <= attack_pct <= 0.60):
            failures.append(f"Gold: attack edge ratio {attack_pct:.1%} outside expected [5%, 60%]")

        # --- PyG tensor ---
        data = torch.load(pyg_path, weights_only=False)
        print(f"[MONITOR] PyG x: {tuple(data.x.shape)} | edge_index: {tuple(data.edge_index.shape)} | edge_attr: {tuple(data.edge_attr.shape)}")

        if data.x.shape[1] != 15:
            failures.append(f"PyG: expected 15 node features, got {data.x.shape[1]}")
        if data.edge_attr.shape[1] != 10:
            failures.append(f"PyG: expected 10 edge features, got {data.edge_attr.shape[1]}")
        if data.y.sum() == 0:
            failures.append("PyG: no attack edges in label tensor")

        # --- Summary ---
        if failures:
            print("[MONITOR] FAILURES:")
            for f in failures:
                print(f"  ✗ {f}")
            raise ValueError(f"Pipeline monitoring failed: {len(failures)} check(s) failed. See logs.")

        print("[MONITOR] All checks passed.")
        return {
            "bronze_rows": bronze_rows,
            "silver_rows": total,
            "gold_nodes":  node_count,
            "gold_edges":  edge_count,
            "attack_pct":  round(attack_pct, 4),
            "pyg_path":    pyg_path,
        }

    done = EmptyOperator(task_id="pipeline_complete")

    # ------------------------------------------------------------------ #
    # DAG wiring                                                           #
    # ------------------------------------------------------------------ #
    new_files         = discover_new_files()
    ingestion_results = ingest_file.expand(file_info=new_files)
    bronze_summary    = summarize_bronze(ingestion_results)
    pyg_output        = export_pyg(run_date="{{ ds_nodash }}")
    monitor_result    = monitor_pipeline(pyg_path=pyg_output)

    (
        ensure_tables
        >> new_files
        >> ingestion_results
        >> bronze_summary
        >> dbt_silver
        >> dbt_gold
        >> dbt_test
        >> pyg_output
        >> monitor_result
        >> done
    )
