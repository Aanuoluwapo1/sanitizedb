import React from 'react';
import { ShieldCheck, X } from 'lucide-react';
import { useMapperStore } from '../store/useMapperStore';
import { STRATEGY_LABELS } from '../types/schema';

export function LivePreviewDrawer() {
  const previewTableId = useMapperStore((s) => s.previewTableId);
  const closePreview = useMapperStore((s) => s.closePreview);
  const nodes = useMapperStore((s) => s.nodes);
  const getMockAnonymizedPreview = useMapperStore((s) => s.getMockAnonymizedPreview);

  if (!previewTableId) return null;

  const node = nodes.find((n) => n.id === previewTableId);
  if (!node) return null;

  const rows = getMockAnonymizedPreview(previewTableId);

  return (
    <div className="fixed inset-x-0 bottom-0 z-50 border-t border-slate-700 bg-slate-950/95 shadow-2xl backdrop-blur">
      <div className="flex items-center justify-between border-b border-slate-800 px-5 py-3">
        <div className="flex items-center gap-3">
          <ShieldCheck className="h-5 w-5 text-emerald-400" />
          <div>
            <h2 className="text-sm font-semibold text-white">
              Live 10-Row Anonymized Preview — <span className="font-mono text-sky-400">{previewTableId}</span>
            </h2>
            <p className="text-xs text-slate-400">
              Masked in-memory by Rust Stream Engine via ephemeral job salt. Raw production PII never leaves the data plane.
            </p>
          </div>
        </div>
        <button
          type="button"
          onClick={closePreview}
          className="rounded-md p-1.5 text-slate-400 hover:bg-slate-800 hover:text-white"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="max-h-72 overflow-auto">
        <table className="w-full text-left text-xs font-mono">
          <thead className="sticky top-0 bg-slate-900 text-slate-300 border-b border-slate-800">
            <tr>
              <th className="px-3 py-2 text-slate-500">#</th>
              {node.data.columns.map((col) => (
                <th key={col.name} className="px-3 py-2">
                  <div>{col.name}</div>
                  <div className="text-[10px] font-sans font-normal text-sky-400">
                    {STRATEGY_LABELS[col.strategy]}
                  </div>
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/70 text-slate-200">
            {rows.map((row) => (
              <tr key={row.rowIndex} className="hover:bg-slate-900/60">
                <td className="px-3 py-1.5 text-slate-500">{row.rowIndex}</td>
                {node.data.columns.map((col) => {
                  const val = row.values[col.name];
                  return (
                    <td key={col.name} className="px-3 py-1.5 whitespace-nowrap">
                      {val === null ? (
                        <span className="italic text-slate-500">NULL</span>
                      ) : (
                        val
                      )}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
