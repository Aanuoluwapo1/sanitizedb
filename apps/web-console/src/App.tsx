import React, { useEffect, useMemo } from 'react';
import { Background, Controls, MiniMap, ReactFlow } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import {
  Activity,
  Award,
  Loader2,
  Play,
  Save,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import { TableNode } from './components/TableNode';
import { LivePreviewDrawer } from './components/LivePreviewDrawer';
import { RunsAndCertificatesDrawer } from './components/RunsAndCertificatesDrawer';
import { SchemaDriftBanner } from './components/SchemaDriftBanner';
import { useMapperStore } from './store/useMapperStore';

export default function App() {
  const nodes = useMapperStore((s) => s.nodes);
  const edges = useMapperStore((s) => s.edges);
  const policyName = useMapperStore((s) => s.policyName);
  const policyVersion = useMapperStore((s) => s.policyVersion);
  const policyDirty = useMapperStore((s) => s.policyDirty);
  const savingPolicy = useMapperStore((s) => s.savingPolicy);
  const saveStatusMessage = useMapperStore((s) => s.saveStatusMessage);
  const recentRuns = useMapperStore((s) => s.recentRuns);
  const isRunningSync = useMapperStore((s) => s.isRunningSync);
  const liveProgress = useMapperStore((s) => s.liveProgress);
  const wsError = useMapperStore((s) => s.wsError);

  const loadActivePolicy = useMapperStore((s) => s.loadActivePolicy);
  const checkSchemaDrift = useMapperStore((s) => s.checkSchemaDrift);
  const savePolicyRules = useMapperStore((s) => s.savePolicyRules);
  const fetchRecentRuns = useMapperStore((s) => s.fetchRecentRuns);
  const triggerSyncRun = useMapperStore((s) => s.triggerSyncRun);
  const toggleRunsDrawer = useMapperStore((s) => s.toggleRunsDrawer);

  const nodeTypes = useMemo(() => ({ tableNode: TableNode }), []);

  useEffect(() => {
    void (async () => {
      await loadActivePolicy();
      await checkSchemaDrift();
      await fetchRecentRuns();
    })();
  }, [loadActivePolicy, checkSchemaDrift, fetchRecentRuns]);

  const totalRisks = nodes.reduce(
    (acc, n) =>
      acc +
      n.data.columns.filter(
        (c) => c.detectedPii !== 'NONE' && c.strategy === 'PASS_THROUGH'
      ).length,
    0
  );

  return (
    <div className="flex h-screen w-screen flex-col bg-slate-950">
      {/* Top Control Bar */}
      <header className="flex items-center justify-between border-b border-slate-800 bg-slate-900/80 px-5 py-3">
        <div className="flex items-center gap-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-sky-500/20 border border-sky-500/40 font-mono font-bold text-sky-300">
            S
          </div>
          <div>
            <h1 className="text-sm font-semibold text-white">
              SanitizeDB{' '}
              <span className="font-normal text-slate-400">
                / {policyName} (v{policyVersion})
              </span>
            </h1>
            <p className="text-[11px] text-slate-400">
              Source: <span className="font-mono text-slate-300">prod_app (read-only)</span> → Target:{' '}
              <span className="font-mono text-slate-300">staging_app</span>
              {saveStatusMessage && (
                <span className="ml-2 text-emerald-400">· {saveStatusMessage}</span>
              )}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          {totalRisks > 0 ? (
            <span className="inline-flex items-center gap-1.5 rounded-full bg-amber-500/15 px-3 py-1 text-xs font-medium text-amber-300 border border-amber-500/30">
              <ShieldAlert className="h-4 w-4" />
              {totalRisks} unmasked PII risk(s)
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-500/15 px-3 py-1 text-xs font-medium text-emerald-300 border border-emerald-500/30">
              <ShieldCheck className="h-4 w-4" />
              GDPR / NDPR / PCI-DSS Ready
            </span>
          )}

          <button
            type="button"
            disabled={!policyDirty || savingPolicy}
            onClick={() => void savePolicyRules()}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700 disabled:opacity-40 transition"
          >
            <Save className="h-3.5 w-3.5" />
            {savingPolicy ? 'Saving...' : 'Save Policy'}
          </button>

          <button
            type="button"
            onClick={() => {
              toggleRunsDrawer(true);
              void fetchRecentRuns();
            }}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700 transition"
          >
            <Award className="h-3.5 w-3.5 text-emerald-400" />
            Runs &amp; Certs
            <span className="rounded-full bg-slate-950 px-1.5 py-0.2 font-mono text-[10px] text-sky-300">
              {recentRuns.length}
            </span>
          </button>

          <button
            type="button"
            disabled={totalRisks > 0 || isRunningSync}
            onClick={() => void triggerSyncRun()}
            className="inline-flex items-center gap-1.5 rounded-lg bg-sky-500 px-3.5 py-1.5 text-xs font-semibold text-slate-950 hover:bg-sky-400 disabled:opacity-40 disabled:cursor-not-allowed transition"
          >
            {isRunningSync ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Play className="h-3.5 w-3.5" />
            )}
            {isRunningSync ? 'Streaming...' : 'Run Zero-Leak Sync'}
          </button>
        </div>
      </header>

      {/* Automated Schema-Drift & Unmapped PII Banner / Quick-Map Controls */}
      <SchemaDriftBanner />

      {/* Real-Time WebSocket Telemetry Strip */}
      {(liveProgress || wsError) && (
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 bg-slate-900/95 px-5 py-2 text-xs">
          <div className="flex items-center gap-2.5">
            <Activity className="h-4 w-4 text-sky-400" />
            {liveProgress && (
              <>
                <span className="font-mono text-slate-300">
                  Job {liveProgress.jobId.slice(0, 8)}
                </span>
                <span
                  className={`rounded-full px-2 py-0.5 text-[10px] font-semibold ${
                    liveProgress.phase === 'COMPLETED'
                      ? 'bg-emerald-500/15 text-emerald-300'
                      : liveProgress.phase === 'FAILED' ||
                        liveProgress.phase === 'BLOCKED_DRIFT'
                      ? 'bg-rose-500/15 text-rose-300'
                      : 'bg-sky-500/15 text-sky-300'
                  }`}
                >
                  {liveProgress.phase}
                </span>
                <span className="font-mono text-slate-200">
                  {liveProgress.totalRowsProcessed.toLocaleString()} rows
                </span>
                {liveProgress.durationMs > 0 && (
                  <span className="font-mono text-slate-400">
                    ({liveProgress.durationMs} ms)
                  </span>
                )}
              </>
            )}
            {wsError && <span className="text-rose-400 font-mono">{wsError}</span>}
          </div>

          <div className="flex items-center gap-2">
            {liveProgress?.saltCommitment && (
              <span className="font-mono text-[11px] text-slate-400">
                Salt: <span className="text-slate-200">{liveProgress.saltCommitment.slice(0, 12)}...</span>
              </span>
            )}
            {liveProgress?.certificateSerial && (
              <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/30 bg-emerald-500/15 px-2.5 py-0.5 font-mono text-[11px] font-semibold text-emerald-300">
                <Award className="h-3.5 w-3.5" />
                {liveProgress.certificateSerial}
              </span>
            )}
          </div>
        </div>
      )}

      {/* React Flow Interactive ER-Diagram Canvas */}
      <main className="relative flex-1">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          fitView
          colorMode="dark"
        >
          <Background color="#1e293b" gap={20} />
          <Controls />
          <MiniMap nodeColor="#38bdf8" maskColor="rgba(2, 6, 23, 0.75)" />
        </ReactFlow>
        <LivePreviewDrawer />
        <RunsAndCertificatesDrawer />
      </main>
    </div>
  );
}
