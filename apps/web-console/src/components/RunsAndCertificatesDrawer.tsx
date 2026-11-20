import React from 'react';
import { Award, CheckCircle2, RefreshCw, ShieldAlert, X } from 'lucide-react';
import { useMapperStore } from '../store/useMapperStore';

export function RunsAndCertificatesDrawer() {
  const open = useMapperStore((s) => s.runsDrawerOpen);
  const toggleRunsDrawer = useMapperStore((s) => s.toggleRunsDrawer);
  const recentRuns = useMapperStore((s) => s.recentRuns);
  const loadingRuns = useMapperStore((s) => s.loadingRuns);
  const fetchRecentRuns = useMapperStore((s) => s.fetchRecentRuns);

  if (!open) return null;

  return (
    <div className="fixed inset-y-0 right-0 z-50 flex w-[520px] flex-col border-l border-slate-700 bg-slate-950/95 shadow-2xl backdrop-blur">
      <div className="flex items-center justify-between border-b border-slate-800 px-5 py-3.5">
        <div className="flex items-center gap-2.5">
          <Award className="h-5 w-5 text-emerald-400" />
          <div>
            <h2 className="text-sm font-semibold text-white">
              Sync Runs &amp; Compliance Certificates
            </h2>
            <p className="text-[11px] text-slate-400">
              Immutable Ed25519 hash-chained audit ledger from Governance Core
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => void fetchRecentRuns()}
            className="rounded-md p-1.5 text-slate-400 hover:bg-slate-800 hover:text-white"
            title="Refresh runs"
          >
            <RefreshCw className={`h-4 w-4 ${loadingRuns ? 'animate-spin' : ''}`} />
          </button>
          <button
            type="button"
            onClick={() => toggleRunsDrawer(false)}
            className="rounded-md p-1.5 text-slate-400 hover:bg-slate-800 hover:text-white"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-auto p-4 space-y-3">
        {recentRuns.length === 0 ? (
          <div className="rounded-lg border border-dashed border-slate-800 p-6 text-center text-xs text-slate-400">
            No recorded sync runs yet. Click <strong>Run Zero-Leak Sync</strong> to execute and mint your first Ed25519 compliance certificate.
          </div>
        ) : (
          recentRuns.map(({ syncJob, certificate }) => {
            const ok = syncJob.status === 'SUCCEEDED';
            const tableSummaries = syncJob.driftSummaryJson?.tables ?? [];
            const durationMs = syncJob.driftSummaryJson?.durationMs;

            return (
              <div
                key={syncJob.id}
                className="rounded-xl border border-slate-800 bg-slate-900/80 p-3.5 text-xs space-y-2.5"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    {ok ? (
                      <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                    ) : (
                      <ShieldAlert className="h-4 w-4 text-rose-400" />
                    )}
                    <span className="font-mono font-semibold text-white">
                      {syncJob.id.slice(0, 8)}...
                    </span>
                    <span
                      className={`rounded-full px-2 py-0.5 text-[10px] font-semibold ${
                        ok
                          ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                          : 'bg-rose-500/15 text-rose-300 border border-rose-500/30'
                      }`}
                    >
                      {syncJob.status}
                    </span>
                  </div>
                  <span className="text-[11px] font-mono text-slate-400">
                    {syncJob.triggerSource}
                  </span>
                </div>

                <div className="grid grid-cols-3 gap-2 rounded-lg bg-slate-950/70 p-2 font-mono text-[11px]">
                  <div>
                    <div className="text-[10px] text-slate-500">Rows Masked</div>
                    <div className="text-slate-100">{syncJob.rowsProcessed.toLocaleString()}</div>
                  </div>
                  <div>
                    <div className="text-[10px] text-slate-500">Duration</div>
                    <div className="text-slate-100">{durationMs != null ? `${durationMs} ms` : '—'}</div>
                  </div>
                  <div>
                    <div className="text-[10px] text-slate-500">Tables</div>
                    <div className="text-slate-100">
                      {syncJob.completedTables}/{syncJob.totalTables}
                    </div>
                  </div>
                </div>

                <div className="font-mono text-[10px] text-slate-400 truncate">
                  Salt SHA-256:{' '}
                  <span className="text-slate-200">{syncJob.saltCommitmentSha256}</span>
                </div>

                {tableSummaries.length > 0 && (
                  <div className="flex flex-wrap gap-1.5">
                    {tableSummaries.map((t) => (
                      <span
                        key={t.qualifiedName}
                        className="rounded bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-300"
                      >
                        {t.qualifiedName}: {t.rowsProcessed} ({t.durationMs}ms)
                      </span>
                    ))}
                  </div>
                )}

                {certificate && (
                  <div className="flex items-center justify-between rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1.5">
                    <div className="flex items-center gap-1.5 text-emerald-300 font-mono text-[11px] font-semibold">
                      <Award className="h-3.5 w-3.5" />
                      {certificate.certificateSerial}
                    </div>
                    <span className="text-[10px] font-mono text-emerald-200/80">
                      {certificate.signatureAlgorithm} · v{certificate.policyVersion}
                    </span>
                  </div>
                )}

                {syncJob.errorMessage && (
                  <div className="rounded border border-rose-500/30 bg-rose-950/40 p-2 font-mono text-[11px] text-rose-300">
                    {syncJob.errorMessage}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
