import React, { useState } from 'react';
import {
  AlertOctagon,
  CheckCircle2,
  PlusCircle,
  RefreshCw,
  Sparkles,
} from 'lucide-react';
import { useMapperStore } from '../store/useMapperStore';
import {
  MaskingStrategy,
  STRATEGY_LABELS,
  UnmappedColumnDrift,
} from '../types/schema';

const ALL_STRATEGIES: MaskingStrategy[] = [
  'DETERMINISTIC_FAKE',
  'PARTIAL_MASK',
  'NULLIFY',
  'SHUFFLE',
  'PASS_THROUGH',
];

function DriftRow({ item }: { item: UnmappedColumnDrift }) {
  const quickMapDriftColumn = useMapperStore((s) => s.quickMapDriftColumn);
  const [selectedStrategy, setSelectedStrategy] = useState<MaskingStrategy>(
    item.suggestedStrategy
  );
  const [domain, setDomain] = useState<string>(item.suggestedDomain ?? '');
  const [busy, setBusy] = useState(false);

  const riskBadgeClass =
    item.riskLevel === 'HIGH'
      ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
      : item.riskLevel === 'MEDIUM'
      ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
      : 'bg-slate-700/60 text-slate-300 border-slate-600';

  const handleApply = async () => {
    setBusy(true);
    await quickMapDriftColumn(item, selectedStrategy, domain);
    setBusy(false);
  };

  return (
    <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-slate-800 bg-slate-950/80 px-3 py-2 text-xs">
      <div className="flex items-center gap-2.5">
        <span
          className={`rounded px-1.5 py-0.5 font-mono text-[10px] font-bold border ${riskBadgeClass}`}
        >
          {item.riskLevel} RISK
        </span>
        <span className="font-mono font-semibold text-white">
          {item.tableId}.<span className="text-rose-300">{item.columnName}</span>
        </span>
        <span className="font-mono text-[11px] text-slate-400">
          ({item.dataType})
        </span>
        {item.detectedPii !== 'NONE' && (
          <span className="rounded bg-purple-500/15 px-1.5 py-0.5 font-mono text-[10px] text-purple-300 border border-purple-500/30">
            {item.detectedPii} · {Math.round(item.piiConfidence * 100)}%
          </span>
        )}
        <span className="text-[11px] text-slate-400">{item.reason}</span>
      </div>

      <div className="flex items-center gap-2">
        {selectedStrategy === 'DETERMINISTIC_FAKE' && (
          <input
            type="text"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="deterministic_domain"
            className="w-36 rounded border border-purple-500/30 bg-slate-900 px-2 py-1 font-mono text-[11px] text-purple-200 focus:border-purple-400 focus:outline-none"
          />
        )}

        <select
          value={selectedStrategy}
          onChange={(e) => setSelectedStrategy(e.target.value as MaskingStrategy)}
          className="rounded-md border border-slate-700 bg-slate-900 px-2 py-1 text-[11px] font-medium text-slate-100 outline-none"
        >
          {ALL_STRATEGIES.map((st) => (
            <option key={st} value={st}>
              {STRATEGY_LABELS[st]}
            </option>
          ))}
        </select>

        <button
          type="button"
          disabled={busy}
          onClick={() => void handleApply()}
          className="inline-flex items-center gap-1 rounded-md bg-emerald-500/20 px-2.5 py-1 text-[11px] font-semibold text-emerald-300 border border-emerald-500/40 hover:bg-emerald-500/30 disabled:opacity-40 transition"
        >
          <PlusCircle className="h-3.5 w-3.5" />
          {busy ? 'Mapping...' : 'Add Rule & Save'}
        </button>
      </div>
    </div>
  );
}

export function SchemaDriftBanner() {
  const driftReport = useMapperStore((s) => s.driftReport);
  const checkingDrift = useMapperStore((s) => s.checkingDrift);
  const checkSchemaDrift = useMapperStore((s) => s.checkSchemaDrift);
  const quickMapAllDriftColumns = useMapperStore(
    (s) => s.quickMapAllDriftColumns
  );

  if (!driftReport) return null;

  if (!driftReport.driftDetected) {
    return (
      <div className="flex items-center justify-between border-b border-slate-800/80 bg-slate-900/40 px-5 py-1.5 text-xs">
        <div className="flex items-center gap-2 text-emerald-400">
          <CheckCircle2 className="h-3.5 w-3.5" />
          <span>
            Schema Drift Gate: <strong>0 unmapped columns</strong> in{' '}
            <code className="font-mono text-slate-300">source-db</code>
          </span>
          {driftReport.schemaFingerprintSha256 && (
            <span className="font-mono text-[11px] text-slate-500">
              · sha256:{driftReport.schemaFingerprintSha256.slice(0, 12)}
            </span>
          )}
        </div>
        <button
          type="button"
          onClick={() => void checkSchemaDrift()}
          className="inline-flex items-center gap-1 rounded px-2 py-0.5 text-[11px] text-slate-400 hover:bg-slate-800 hover:text-slate-200 transition"
        >
          <RefreshCw
            className={`h-3 w-3 ${checkingDrift ? 'animate-spin' : ''}`}
          />
          Scan Source Schema
        </button>
      </div>
    );
  }

  return (
    <div className="border-b border-rose-500/40 bg-rose-950/30 px-5 py-2.5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <AlertOctagon className="h-4 w-4 text-rose-400 shrink-0" />
          <div className="text-xs">
            <span className="font-semibold text-rose-200">
              Schema Drift Detected in Production Source DB:
            </span>{' '}
            <span className="text-rose-300">
              {driftReport.unmappedColumns.length} unmapped column(s) (
              <strong>{driftReport.highRiskCount} HIGH</strong>,{' '}
              {driftReport.mediumRiskCount} MEDIUM, {driftReport.lowRiskCount}{' '}
              LOW)
            </span>
            {driftReport.syncBlocked && (
              <span className="ml-2 rounded-full bg-rose-500/20 px-2 py-0.5 font-mono text-[10px] font-bold text-rose-200 border border-rose-500/40">
                FAIL-CLOSED GATE ACTIVE: SYNC BLOCKED UNTIL HIGH-RISK PII MAPPED
              </span>
            )}
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => void quickMapAllDriftColumns()}
            className="inline-flex items-center gap-1.5 rounded-md bg-purple-500/20 px-2.5 py-1 text-xs font-semibold text-purple-200 border border-purple-500/40 hover:bg-purple-500/30 transition"
          >
            <Sparkles className="h-3.5 w-3.5" />
            Quick-Map All Recommended Rules
          </button>
          <button
            type="button"
            onClick={() => void checkSchemaDrift()}
            className="inline-flex items-center gap-1 rounded-md border border-slate-700 bg-slate-900 px-2 py-1 text-xs text-slate-300 hover:bg-slate-800 transition"
          >
            <RefreshCw
              className={`h-3.5 w-3.5 ${checkingDrift ? 'animate-spin' : ''}`}
            />
            Re-Scan
          </button>
        </div>
      </div>

      <div className="mt-2 space-y-1.5">
        {driftReport.unmappedColumns.map((item) => (
          <DriftRow
            key={`${item.tableId}.${item.columnName}`}
            item={item}
          />
        ))}
      </div>
    </div>
  );
}
