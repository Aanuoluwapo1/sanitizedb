use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use futures_util::{pin_mut, SinkExt, TryStreamExt};
use thiserror::Error;
use tokio::sync::mpsc;
use tokio_postgres::Client;
use tracing::{info, instrument, warn};

use crate::detector::{classify_column_heuristic, PiiRiskLevel};
use crate::masker::{ColumnRule, DeterministicMasker, MaskError, MaskingStrategy};

#[derive(Debug, Error)]
pub enum PipelineError {
    #[error("postgres error: {0}")]
    Postgres(#[from] tokio_postgres::Error),
    #[error("masking error: {0}")]
    Mask(#[from] MaskError),
    #[error("schema/policy validation failed: {0}")]
    SchemaValidation(String),
    #[error("downstream writer channel closed prematurely")]
    ChannelClosed,
    #[error("UTF-8 decode error in COPY stream: {0}")]
    Utf8(#[from] std::str::Utf8Error),
}

#[derive(Debug, Clone)]
pub struct TableStreamConfig {
    pub schema_name: String,
    pub table_name: String,
    pub column_rules: Vec<ColumnRule>,
    pub truncate_target: bool,
    pub channel_capacity: usize,
}

#[derive(Debug, Clone)]
pub struct TableStreamResult {
    pub qualified_table: String,
    pub rows_processed: u64,
    pub bytes_streamed: u64,
    pub duration_ms: u64,
}

#[derive(Debug, Clone)]
pub struct ProgressSnapshot {
    pub qualified_table: String,
    pub rows_processed: u64,
    pub bytes_streamed: u64,
    pub rows_per_second: f64,
    pub channel_depth: usize,
    pub duration_ms: u64,
    pub completed: bool,
}

fn validate_sql_identifier(ident: &str, kind: &str) -> Result<(), PipelineError> {
    if ident.is_empty()
        || ident.len() > 128
        || !ident
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err(PipelineError::SchemaValidation(format!(
            "invalid SQL {kind} identifier '{ident}'"
        )));
    }
    Ok(())
}

/// Returns a map of `column_name -> pg_type_sql` for the given `(schema, table)`.
async fn fetch_table_column_types(
    client: &Client,
    schema: &str,
    table: &str,
) -> Result<HashMap<String, String>, PipelineError> {
    let rows = client
        .query(
            "SELECT column_name, data_type, character_maximum_length
             FROM information_schema.columns
             WHERE table_schema = $1 AND table_name = $2
             ORDER BY ordinal_position",
            &[&schema, &table],
        )
        .await?;

    let mut map = HashMap::with_capacity(rows.len());
    for r in rows {
        let col_name: String = r.get(0);
        let data_type: String = r.get(1);
        let char_len: Option<i32> = r.get(2);
        let sql_type = match (data_type.as_str(), char_len) {
            ("character varying", Some(n)) if n > 0 => format!("VARCHAR({n})"),
            ("character varying", _) => "TEXT".into(),
            ("character", Some(n)) if n > 0 => format!("CHAR({n})"),
            ("character", _) => "TEXT".into(),
            ("timestamp with time zone", _) => "TIMESTAMPTZ".into(),
            ("timestamp without time zone", _) => "TIMESTAMP".into(),
            ("USER-DEFINED" | "ARRAY", _) => "TEXT".into(),
            other => other.0.to_ascii_uppercase(),
        };
        map.insert(col_name, sql_type);
    }
    Ok(map)
}

/// Fail-closed pre-flight validation across both source and target databases.
/// Runs BEFORE any target table is truncated or modified:
/// 1. Fails fast if any configured table or column is missing in `source-db`.
/// 2. Detects unmapped columns in `source-db` (schema drift) and fails closed if any
///    unmapped column carries HIGH PII risk (`email`, `phone`, `nin`, `ssn`, `card`, etc.).
/// 3. Automatically reconciles `target-db` when a newly added `source-db` column has been
///    explicitly mapped in the policy (`ALTER TABLE ... ADD COLUMN IF NOT EXISTS`), or
///    fails closed if `target-db` table is missing.
pub async fn validate_policy_and_schemas(
    source: &Client,
    target: &Client,
    tables: &[TableStreamConfig],
) -> Result<(), PipelineError> {
    if tables.is_empty() {
        return Err(PipelineError::SchemaValidation(
            "policy contains zero tables to sync".into(),
        ));
    }

    let mut unmapped_high_risk: Vec<String> = Vec::new();

    for tbl in tables {
        validate_sql_identifier(&tbl.schema_name, "schema")?;
        validate_sql_identifier(&tbl.table_name, "table")?;
        let fq = format!("{}.{}", tbl.schema_name, tbl.table_name);

        if tbl.column_rules.is_empty() {
            return Err(PipelineError::SchemaValidation(format!(
                "table '{fq}' has zero column masking rules"
            )));
        }

        let src_cols = fetch_table_column_types(source, &tbl.schema_name, &tbl.table_name).await?;
        if src_cols.is_empty() {
            return Err(PipelineError::SchemaValidation(format!(
                "source table '{fq}' does not exist or has no accessible columns"
            )));
        }

        let mut tgt_cols =
            fetch_table_column_types(target, &tbl.schema_name, &tbl.table_name).await?;
        if tgt_cols.is_empty() {
            return Err(PipelineError::SchemaValidation(format!(
                "target table '{fq}' does not exist or has no accessible columns"
            )));
        }

        let mut configured_cols = HashSet::with_capacity(tbl.column_rules.len());
        for rule in &tbl.column_rules {
            validate_sql_identifier(&rule.column_name, "column")?;
            if !configured_cols.insert(rule.column_name.clone()) {
                return Err(PipelineError::SchemaValidation(format!(
                    "duplicate column rule '{fq}.{}'",
                    rule.column_name
                )));
            }
            let Some(src_sql_type) = src_cols.get(&rule.column_name) else {
                return Err(PipelineError::SchemaValidation(format!(
                    "expected source column '{fq}.{}' is missing in source-db",
                    rule.column_name
                )));
            };

            // If the column exists in source-db and is explicitly mapped in the policy,
            // ensure target-db also has the column so schema-drifted columns sync cleanly once mapped.
            if !tgt_cols.contains_key(&rule.column_name) {
                let alter_sql = format!(
                    "ALTER TABLE \"{}\".\"{}\" ADD COLUMN IF NOT EXISTS \"{}\" {};",
                    tbl.schema_name, tbl.table_name, rule.column_name, src_sql_type
                );
                info!(
                    column = %format!("{fq}.{}", rule.column_name),
                    sql_type = %src_sql_type,
                    "Reconciling newly mapped drift column on target-db"
                );
                target.batch_execute(&alter_sql).await?;
                tgt_cols.insert(rule.column_name.clone(), src_sql_type.clone());
            }
        }

        // Check for unmapped source columns (Schema Drift & Unmapped PII Gate)
        for src_col in src_cols.keys() {
            if !configured_cols.contains(src_col) {
                let detection = classify_column_heuristic(src_col);
                if detection.risk_level == PiiRiskLevel::High {
                    unmapped_high_risk.push(format!(
                        "{fq}.{src_col} [HIGH risk: pattern '{}']",
                        detection.matched_pattern
                    ));
                } else {
                    warn!(
                        column = %format!("{fq}.{src_col}"),
                        risk = detection.risk_level.as_str(),
                        "Unmapped non-HIGH column detected in source-db (omitted from COPY stream)"
                    );
                }
            }
        }
    }

    if !unmapped_high_risk.is_empty() {
        unmapped_high_risk.sort();
        return Err(PipelineError::SchemaValidation(format!(
            "SCHEMA_DRIFT_BLOCKED: unmapped HIGH-risk PII column(s) detected in source-db: {}. Map these columns in the active policy before running a sync.",
            unmapped_high_risk.join(", ")
        )));
    }

    Ok(())
}

/// Atomically truncates target tables in reverse topological (child-first) FK order
/// within a single PostgreSQL transaction so repeat syncs are strictly idempotent.
pub async fn truncate_targets_in_reverse_fk_order(
    target: &mut Client,
    tables: &[TableStreamConfig],
) -> Result<(), PipelineError> {
    let to_truncate: Vec<String> = tables
        .iter()
        .rev()
        .filter(|t| t.truncate_target)
        .map(|t| format!("\"{}\".\"{}\"", t.schema_name, t.table_name))
        .collect();

    if to_truncate.is_empty() {
        return Ok(());
    }

    let tx = target.transaction().await?;
    for qualified in &to_truncate {
        tx.batch_execute(&format!(
            "TRUNCATE TABLE {qualified} RESTART IDENTITY CASCADE;"
        ))
        .await?;
    }
    tx.commit().await?;
    info!(
        tables = ?to_truncate,
        "Atomically truncated target tables in reverse FK order"
    );
    Ok(())
}

/// Zero-disk-leak streaming row transformer.
pub struct StreamingTableTransformer<M: DeterministicMasker + 'static> {
    masker: Arc<M>,
}

impl<M: DeterministicMasker + 'static> StreamingTableTransformer<M> {
    pub fn new(masker: Arc<M>) -> Self {
        Self { masker }
    }

    #[instrument(skip(self, source, target, progress_tx), fields(table = %cfg.table_name))]
    pub async fn stream_table(
        &self,
        source: &Client,
        target: &Client,
        cfg: &TableStreamConfig,
        progress_tx: mpsc::Sender<ProgressSnapshot>,
    ) -> Result<TableStreamResult, PipelineError> {
        let qualified = format!("\"{}\".\"{}\"", cfg.schema_name, cfg.table_name);
        let col_list = cfg
            .column_rules
            .iter()
            .map(|r| format!("\"{}\"", r.column_name))
            .collect::<Vec<_>>()
            .join(", ");

        let capacity = cfg.channel_capacity.max(64);
        let (tx, mut rx) = mpsc::channel::<Bytes>(capacity);

        let copy_out_sql = format!("COPY {qualified} ({col_list}) TO STDOUT (FORMAT text)");
        let copy_in_sql = format!("COPY {qualified} ({col_list}) FROM STDIN (FORMAT text)");

        let reader_stream = source.copy_out(&copy_out_sql).await?;
        let writer_sink = target.copy_in(&copy_in_sql).await?;

        let masker = Arc::clone(&self.masker);
        let rules = cfg.column_rules.clone();
        let qualified_label = format!("{}.{}", cfg.schema_name, cfg.table_name);
        let start = Instant::now();

        let producer = async move {
            pin_mut!(reader_stream);
            let mut carry = Vec::<u8>::with_capacity(8192);
            let mut rows_processed = 0u64;
            let mut bytes_streamed = 0u64;

            while let Some(chunk) = reader_stream.try_next().await? {
                carry.extend_from_slice(&chunk);

                let mut batch_out = Vec::<u8>::with_capacity(chunk.len() + 256);
                let mut start_idx = 0usize;

                while let Some(rel_nl) = carry[start_idx..].iter().position(|&b| b == b'\n') {
                    let end_idx = start_idx + rel_nl;
                    let line = std::str::from_utf8(&carry[start_idx..end_idx])?;
                    let masked_line = transform_copy_text_row(line, &rules, masker.as_ref())?;
                    batch_out.extend_from_slice(masked_line.as_bytes());
                    batch_out.push(b'\n');

                    rows_processed += 1;
                    start_idx = end_idx + 1;
                }

                if start_idx > 0 {
                    carry.drain(..start_idx);
                }

                if !batch_out.is_empty() {
                    bytes_streamed += batch_out.len() as u64;
                    let channel_depth = capacity.saturating_sub(tx.capacity());
                    tx.send(Bytes::from(batch_out))
                        .await
                        .map_err(|_| PipelineError::ChannelClosed)?;

                    if rows_processed % 1_000 == 0 {
                        let elapsed = start.elapsed();
                        let elapsed_secs = elapsed.as_secs_f64().max(0.001);
                        let _ = progress_tx.try_send(ProgressSnapshot {
                            qualified_table: qualified_label.clone(),
                            rows_processed,
                            bytes_streamed,
                            rows_per_second: rows_processed as f64 / elapsed_secs,
                            channel_depth,
                            duration_ms: elapsed.as_millis() as u64,
                            completed: false,
                        });
                    }
                }
            }

            if !carry.is_empty() {
                let line = std::str::from_utf8(&carry)?;
                if !line.is_empty() {
                    let masked_line = transform_copy_text_row(line, &rules, masker.as_ref())?;
                    let mut final_batch = Vec::with_capacity(masked_line.len() + 1);
                    final_batch.extend_from_slice(masked_line.as_bytes());
                    final_batch.push(b'\n');
                    bytes_streamed += final_batch.len() as u64;
                    rows_processed += 1;
                    tx.send(Bytes::from(final_batch))
                        .await
                        .map_err(|_| PipelineError::ChannelClosed)?;
                }
                carry.clear();
            }

            drop(tx);

            let elapsed = start.elapsed();
            let elapsed_secs = elapsed.as_secs_f64().max(0.001);
            let duration_ms = elapsed.as_millis() as u64;
            let _ = progress_tx
                .send(ProgressSnapshot {
                    qualified_table: qualified_label.clone(),
                    rows_processed,
                    bytes_streamed,
                    rows_per_second: rows_processed as f64 / elapsed_secs,
                    channel_depth: 0,
                    duration_ms,
                    completed: true,
                })
                .await;

            Ok::<TableStreamResult, PipelineError>(TableStreamResult {
                qualified_table: qualified_label,
                rows_processed,
                bytes_streamed,
                duration_ms,
            })
        };

        let consumer = async move {
            pin_mut!(writer_sink);
            while let Some(masked_batch) = rx.recv().await {
                writer_sink.send(masked_batch).await?;
            }
            writer_sink.finish().await?;
            Ok::<(), PipelineError>(())
        };

        let (result, ()) = tokio::try_join!(producer, consumer)?;
        info!(
            table = %result.qualified_table,
            rows = result.rows_processed,
            duration_ms = result.duration_ms,
            "Completed zero-leak table stream"
        );
        Ok(result)
    }
}

/// Transforms a single PostgreSQL `COPY (FORMAT text)` tab-delimited row in memory.
pub fn transform_copy_text_row(
    raw_line: &str,
    rules: &[ColumnRule],
    masker: &dyn DeterministicMasker,
) -> Result<String, MaskError> {
    let fields: Vec<&str> = raw_line.split('\t').collect();
    let mut masked_fields = Vec::with_capacity(fields.len());

    for (idx, field) in fields.iter().enumerate() {
        let raw_opt = if *field == r"\N" { None } else { Some(*field) };
        let Some(rule) = rules.get(idx) else {
            masked_fields.push(r"\N".to_owned());
            continue;
        };

        if rule.strategy == MaskingStrategy::PassThrough {
            masked_fields.push((*field).to_owned());
            continue;
        }

        let unescaped = raw_opt.map(unescape_pg_copy_field);
        let masked_opt = masker.mask_value(unescaped.as_deref(), rule)?;
        match masked_opt {
            None => masked_fields.push(r"\N".to_owned()),
            Some(val) => masked_fields.push(escape_pg_copy_field(&val)),
        }
    }

    Ok(masked_fields.join("\t"))
}

fn unescape_pg_copy_field(s: &str) -> String {
    s.replace(r"\t", "\t")
        .replace(r"\n", "\n")
        .replace(r"\r", "\r")
        .replace(r"\\", r"\")
}

fn escape_pg_copy_field(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str(r"\\"),
            '\t' => out.push_str(r"\t"),
            '\n' => out.push_str(r"\n"),
            '\r' => out.push_str(r"\r"),
            other => out.push(other),
        }
    }
    out
}
