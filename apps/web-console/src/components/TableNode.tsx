import React, { memo } from 'react';
import { Handle, NodeProps, Position } from '@xyflow/react';
import { AlertOctagon, AlertTriangle, Eye, KeyRound, Link2, ShieldCheck, Table2 } from 'lucide-react';
import { MaskingStrategy, STRATEGY_LABELS, TableNodeData } from '../types/schema';
import { useMapperStore } from '../store/useMapperStore';

const ALL_STRATEGIES: MaskingStrategy[] = [
  'DETERMINISTIC_FAKE',
  'NULLIFY',
  'PARTIAL_MASK',
  'SHUFFLE',
  'PASS_THROUGH',
];

function TableNodeComponent({ data }: NodeProps) {
  const tableData = data as TableNodeData;
  const updateColumnStrategy = useMapperStore((s) => s.updateColumnStrategy);
  const updateColumnDomain = useMapperStore((s) => s.updateColumnDomain);
  const openPreview = useMapperStore((s) => s.openPreview);

  const piiCount = tableData.columns.filter((c) => c.detectedPii !== 'NONE').length;
  const unmappedCount = tableData.columns.filter((c) => c.isUnmapped).length;
  const unmaskedPiiCount = tableData.columns.filter(
    (c) => c.detectedPii !== 'NONE' && c.strategy === 'PASS_THROUGH'
  ).length;

  return (
    <div className="w-[430px] rounded-xl border border-slate-700 bg-slate-900/95 shadow-2xl backdrop-blur">
      {/* Table Header */}
      <div className="flex items-center justify-between border-b border-slate-800 bg-slate-800/70 px-3.5 py-2.5 rounded-t-xl">
        <div className="flex items-center gap-2">
          <Table2 className="h-4 w-4 text-sky-400" />
          <div>
            <div className="text-xs font-mono text-slate-400">{tableData.schemaName}</div>
            <div className="text-sm font-semibold text-white leading-tight">
              {tableData.tableName}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="rounded-full bg-slate-900 px-2 py-0.5 text-[11px] font-mono text-slate-300 border border-slate-700">
            ~{tableData.estimatedRows.toLocaleString()} rows
          </span>
          <button
            type="button"
            onClick={() => openPreview(tableData.tableId)}
            className="nodrag inline-flex items-center gap-1 rounded-md bg-sky-500/15 px-2 py-1 text-xs font-medium text-sky-300 border border-sky-500/30 hover:bg-sky-500/25 transition"
            title="Preview 10 live anonymized rows"
          >
            <Eye className="h-3.5 w-3.5" />
            Preview
          </button>
        </div>
      </div>

      {/* Compliance Summary Banner */}
      <div className="flex items-center justify-between px-3.5 py-1.5 text-[11px] border-b border-slate-800/80 bg-slate-950/40">
        <span className="text-slate-400">
          Auto-flagged PII columns: <strong className="text-slate-200">{piiCount}</strong>
        </span>
        {unmappedCount > 0 ? (
          <span className="inline-flex items-center gap-1 text-rose-400 font-semibold">
            <AlertOctagon className="h-3.5 w-3.5" />
            {unmappedCount} unmapped drift col(s)
          </span>
        ) : unmaskedPiiCount > 0 ? (
          <span className="inline-flex items-center gap-1 text-amber-400 font-medium">
            <AlertTriangle className="h-3.5 w-3.5" />
            {unmaskedPiiCount} PII pass-through risk
          </span>
        ) : (
          <span className="inline-flex items-center gap-1 text-emerald-400 font-medium">
            <ShieldCheck className="h-3.5 w-3.5" />
            Policy compliant
          </span>
        )}
      </div>

      {/* Columns List */}
      <div className="divide-y divide-slate-800/70">
        {tableData.columns.map((col) => {
          const isPii = col.detectedPii !== 'NONE';
          const isRisk = isPii && col.strategy === 'PASS_THROUGH';

          return (
            <div
              key={col.name}
              className={`relative flex items-center justify-between gap-2 px-3.5 py-2 text-xs ${
                col.isUnmapped
                  ? 'bg-rose-950/40 border-l-2 border-l-rose-500'
                  : isRisk
                  ? 'bg-amber-950/30'
                  : 'hover:bg-slate-800/40'
              }`}
            >
              <Handle
                type="target"
                position={Position.Left}
                id={`${tableData.tableId}:${col.name}:target`}
                className="!h-2.5 !w-2.5 !bg-sky-400 !border-slate-900"
              />

              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-1.5">
                  {col.isPrimaryKey && <KeyRound className="h-3 w-3 text-amber-400 shrink-0" />}
                  {col.isForeignKey && <Link2 className="h-3 w-3 text-sky-400 shrink-0" />}
                  <span className="font-mono font-medium text-slate-100 truncate">{col.name}</span>
                  <span className="text-[10px] font-mono text-slate-500">{col.dataType}</span>
                </div>

                <div className="mt-1 flex flex-wrap items-center gap-1.5">
                  {col.isUnmapped && (
                    <span className="inline-flex items-center rounded bg-rose-500/25 px-1.5 py-0.5 text-[10px] font-bold text-rose-200 border border-rose-500/50">
                      UNMAPPED · {col.riskLevel ?? 'HIGH'}
                    </span>
                  )}
                  {isPii && (
                    <span className="inline-flex items-center rounded bg-rose-500/15 px-1.5 py-0.5 text-[10px] font-semibold text-rose-300 border border-rose-500/30">
                      {col.detectedPii} · {Math.round(col.piiConfidence * 100)}%
                    </span>
                  )}
                  {col.strategy === 'DETERMINISTIC_FAKE' && (
                    <input
                      type="text"
                      value={col.deterministicDomain ?? ''}
                      onChange={(e) =>
                        updateColumnDomain(tableData.tableId, col.name, e.target.value)
                      }
                      placeholder="deterministic_domain"
                      title="Shared HMAC domain for cross-table join determinism"
                      className="nodrag w-36 rounded bg-purple-500/10 px-1.5 py-0.5 text-[10px] font-mono text-purple-200 border border-purple-500/30 focus:border-purple-400 focus:outline-none placeholder:text-purple-400/50"
                    />
                  )}
                </div>
              </div>

              <select
                value={col.strategy}
                onChange={(e) =>
                  updateColumnStrategy(
                    tableData.tableId,
                    col.name,
                    e.target.value as MaskingStrategy
                  )
                }
                className={`nodrag rounded-md border px-2 py-1 text-[11px] font-medium outline-none transition ${
                  col.isUnmapped
                    ? 'border-rose-500/60 bg-rose-950/70 text-rose-200'
                    : isRisk
                    ? 'border-amber-500/60 bg-amber-950/60 text-amber-200'
                    : col.strategy === 'DETERMINISTIC_FAKE'
                    ? 'border-purple-500/40 bg-slate-950 text-purple-200'
                    : 'border-slate-700 bg-slate-950 text-slate-200'
                }`}
              >
                {ALL_STRATEGIES.map((strategy) => (
                  <option key={strategy} value={strategy}>
                    {STRATEGY_LABELS[strategy]}
                  </option>
                ))}
              </select>

              <Handle
                type="source"
                position={Position.Right}
                id={`${tableData.tableId}:${col.name}:source`}
                className="!h-2.5 !w-2.5 !bg-purple-400 !border-slate-900"
              />
            </div>
          );
        })}
      </div>
    </div>
  );
}

export const TableNode = memo(TableNodeComponent);
