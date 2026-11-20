import { create } from 'zustand';
import { Edge, Node } from '@xyflow/react';
import {
  LiveProgressEvent,
  MaskingStrategy,
  PolicyDriftInspectionReport,
  PreviewRow,
  SyncRunResponse,
  TableNodeData,
  UnmappedColumnDrift,
} from '../types/schema';

const ORCHESTRATOR_URL =
  import.meta.env.VITE_ORCHESTRATOR_URL ?? 'http://localhost:8080';
const GOVERNANCE_URL =
  import.meta.env.VITE_GOVERNANCE_URL ?? 'http://localhost:8081';

interface BackendPolicy {
  id: string;
  orgId: string;
  name: string;
  version: number;
  rulesSha256: string;
  rulesJson: Record<
    string,
    Record<
      string,
      {
        strategy: MaskingStrategy;
        semanticType?: string;
        deterministicDomain?: string;
        preservePrefix?: number;
        preserveSuffix?: number;
      }
    >
  >;
}

interface MapperState {
  policyId: string;
  policyName: string;
  policyVersion: number;
  policyDirty: boolean;
  savingPolicy: boolean;
  saveStatusMessage: string | null;

  nodes: Node<TableNodeData>[];
  edges: Edge[];
  previewTableId: string | null;

  driftReport: PolicyDriftInspectionReport | null;
  checkingDrift: boolean;

  runsDrawerOpen: boolean;
  recentRuns: SyncRunResponse[];
  loadingRuns: boolean;

  isRunningSync: boolean;
  liveProgress: LiveProgressEvent | null;
  wsError: string | null;

  updateColumnStrategy: (
    tableId: string,
    columnName: string,
    strategy: MaskingStrategy
  ) => void;
  updateColumnDomain: (
    tableId: string,
    columnName: string,
    domain: string
  ) => void;
  openPreview: (tableId: string) => void;
  closePreview: () => void;
  toggleRunsDrawer: (open?: boolean) => void;
  loadActivePolicy: () => Promise<void>;
  checkSchemaDrift: () => Promise<void>;
  quickMapDriftColumn: (
    drift: UnmappedColumnDrift,
    strategy: MaskingStrategy,
    domain?: string
  ) => Promise<void>;
  quickMapAllDriftColumns: () => Promise<void>;
  savePolicyRules: () => Promise<void>;
  fetchRecentRuns: () => Promise<void>;
  triggerSyncRun: () => Promise<void>;
  getMockAnonymizedPreview: (tableId: string) => PreviewRow[];
}

const initialNodes: Node<TableNodeData>[] = [
  {
    id: 'public.users',
    type: 'tableNode',
    position: { x: 30, y: 30 },
    data: {
      tableId: 'public.users',
      schemaName: 'public',
      tableName: 'users',
      estimatedRows: 5,
      columns: [
        { name: 'id', dataType: 'bigint', isPrimaryKey: true, detectedPii: 'NONE', piiConfidence: 0, strategy: 'PASS_THROUGH' },
        { name: 'external_uid', dataType: 'uuid', detectedPii: 'NONE', piiConfidence: 0, strategy: 'PASS_THROUGH' },
        { name: 'full_name', dataType: 'varchar(160)', detectedPii: 'FULL_NAME', piiConfidence: 0.94, strategy: 'DETERMINISTIC_FAKE', deterministicDomain: 'identity.full_name' },
        { name: 'email', dataType: 'varchar(255)', detectedPii: 'EMAIL', piiConfidence: 0.99, strategy: 'DETERMINISTIC_FAKE', deterministicDomain: 'identity.email' },
        { name: 'phone_number', dataType: 'varchar(32)', detectedPii: 'PHONE', piiConfidence: 0.96, strategy: 'DETERMINISTIC_FAKE', deterministicDomain: 'identity.phone' },
        { name: 'national_id', dataType: 'varchar(32)', detectedPii: 'NATIONAL_ID', piiConfidence: 0.97, strategy: 'DETERMINISTIC_FAKE', deterministicDomain: 'identity.national_id' },
        { name: 'date_of_birth', dataType: 'date', detectedPii: 'DATE_OF_BIRTH', piiConfidence: 0.92, strategy: 'DETERMINISTIC_FAKE' },
        { name: 'signup_ip', dataType: 'varchar(45)', detectedPii: 'IP_ADDRESS', piiConfidence: 0.92, strategy: 'PARTIAL_MASK', preservePrefix: 4, preserveSuffix: 0 },
        { name: 'country_code', dataType: 'char(2)', detectedPii: 'NONE', piiConfidence: 0, strategy: 'PASS_THROUGH' },
        { name: 'tier', dataType: 'varchar(20)', detectedPii: 'NONE', piiConfidence: 0, strategy: 'PASS_THROUGH' },
        { name: 'created_at', dataType: 'timestamptz', detectedPii: 'NONE', piiConfidence: 0, strategy: 'PASS_THROUGH' },
      ],
    },
  },
  {
    id: 'public.payment_methods',
    type: 'tableNode',
    position: { x: 520, y: 20 },
    data: {
      tableId: 'public.payment_methods',
      schemaName: 'public',
      tableName: 'payment_methods',
      estimatedRows: 4,
      columns: [
        { name: 'id', dataType: 'bigint', isPrimaryKey: true, detectedPii: 'NONE', piiConfidence: 0, strategy: 'PASS_THROUGH' },
        { name: 'user_id', dataType: 'bigint', isForeignKey: true, detectedPii: 'NONE', piiConfidence: 0, strategy: 'PASS_THROUGH' },
        { name: 'cardholder_name', dataType: 'varchar(160)', detectedPii: 'FULL_NAME', piiConfidence: 0.93, strategy: 'DETERMINISTIC_FAKE', deterministicDomain: 'identity.full_name' },
        { name: 'card_number', dataType: 'varchar(32)', detectedPii: 'CREDIT_CARD', piiConfidence: 0.99, strategy: 'PARTIAL_MASK', preservePrefix: 0, preserveSuffix: 4 },
        { name: 'billing_email', dataType: 'varchar(255)', detectedPii: 'EMAIL', piiConfidence: 0.98, strategy: 'DETERMINISTIC_FAKE', deterministicDomain: 'identity.email' },
        { name: 'billing_zip', dataType: 'varchar(16)', detectedPii: 'NONE', piiConfidence: 0, strategy: 'PARTIAL_MASK', preservePrefix: 2, preserveSuffix: 0 },
        { name: 'created_at', dataType: 'timestamptz', detectedPii: 'NONE', piiConfidence: 0, strategy: 'PASS_THROUGH' },
      ],
    },
  },
  {
    id: 'public.orders',
    type: 'tableNode',
    position: { x: 520, y: 400 },
    data: {
      tableId: 'public.orders',
      schemaName: 'public',
      tableName: 'orders',
      estimatedRows: 6,
      columns: [
        { name: 'id', dataType: 'bigint', isPrimaryKey: true, detectedPii: 'NONE', piiConfidence: 0, strategy: 'PASS_THROUGH' },
        { name: 'user_id', dataType: 'bigint', isForeignKey: true, detectedPii: 'NONE', piiConfidence: 0, strategy: 'PASS_THROUGH' },
        { name: 'customer_email', dataType: 'varchar(255)', detectedPii: 'EMAIL', piiConfidence: 0.99, strategy: 'DETERMINISTIC_FAKE', deterministicDomain: 'identity.email' },
        { name: 'shipping_address', dataType: 'text', detectedPii: 'STREET_ADDRESS', piiConfidence: 0.91, strategy: 'DETERMINISTIC_FAKE' },
        { name: 'amount_cents', dataType: 'integer', detectedPii: 'NONE', piiConfidence: 0, strategy: 'PASS_THROUGH' },
        { name: 'currency', dataType: 'char(3)', detectedPii: 'NONE', piiConfidence: 0, strategy: 'PASS_THROUGH' },
        { name: 'status', dataType: 'varchar(32)', detectedPii: 'NONE', piiConfidence: 0, strategy: 'PASS_THROUGH' },
        { name: 'created_at', dataType: 'timestamptz', detectedPii: 'NONE', piiConfidence: 0, strategy: 'PASS_THROUGH' },
      ],
    },
  },
  {
    id: 'public.audit_logs',
    type: 'tableNode',
    position: { x: 1010, y: 180 },
    data: {
      tableId: 'public.audit_logs',
      schemaName: 'public',
      tableName: 'audit_logs',
      estimatedRows: 5,
      columns: [
        { name: 'id', dataType: 'bigint', isPrimaryKey: true, detectedPii: 'NONE', piiConfidence: 0, strategy: 'PASS_THROUGH' },
        { name: 'user_id', dataType: 'bigint', isForeignKey: true, detectedPii: 'NONE', piiConfidence: 0, strategy: 'PASS_THROUGH' },
        { name: 'actor_email', dataType: 'varchar(255)', detectedPii: 'EMAIL', piiConfidence: 0.99, strategy: 'DETERMINISTIC_FAKE', deterministicDomain: 'identity.email' },
        { name: 'ip_address', dataType: 'varchar(45)', detectedPii: 'IP_ADDRESS', piiConfidence: 0.95, strategy: 'PARTIAL_MASK', preservePrefix: 4, preserveSuffix: 0 },
        { name: 'action', dataType: 'varchar(64)', detectedPii: 'NONE', piiConfidence: 0, strategy: 'PASS_THROUGH' },
        { name: 'user_agent', dataType: 'text', detectedPii: 'NONE', piiConfidence: 0, strategy: 'PASS_THROUGH' },
        { name: 'created_at', dataType: 'timestamptz', detectedPii: 'NONE', piiConfidence: 0, strategy: 'PASS_THROUGH' },
      ],
    },
  },
];

const initialEdges: Edge[] = [
  {
    id: 'fk-users-payments',
    source: 'public.users',
    sourceHandle: 'public.users:id:source',
    target: 'public.payment_methods',
    targetHandle: 'public.payment_methods:user_id:target',
    animated: true,
    label: 'FK user_id',
    style: { stroke: '#38bdf8', strokeWidth: 2 },
  },
  {
    id: 'fk-users-orders',
    source: 'public.users',
    sourceHandle: 'public.users:id:source',
    target: 'public.orders',
    targetHandle: 'public.orders:user_id:target',
    animated: true,
    label: 'FK user_id',
    style: { stroke: '#38bdf8', strokeWidth: 2 },
  },
  {
    id: 'domain-email-orders',
    source: 'public.users',
    sourceHandle: 'public.users:email:source',
    target: 'public.orders',
    targetHandle: 'public.orders:customer_email:target',
    animated: true,
    label: 'HMAC identity.email',
    style: { stroke: '#a855f7', strokeWidth: 1.75, strokeDasharray: '6 4' },
  },
  {
    id: 'domain-email-audit',
    source: 'public.orders',
    sourceHandle: 'public.orders:customer_email:source',
    target: 'public.audit_logs',
    targetHandle: 'public.audit_logs:actor_email:target',
    animated: true,
    label: 'HMAC identity.email',
    style: { stroke: '#a855f7', strokeWidth: 1.75, strokeDasharray: '6 4' },
  },
];

let activeSocket: WebSocket | null = null;

export const useMapperStore = create<MapperState>((set, get) => ({
  policyId: '00000000-0000-0000-0000-000000000100',
  policyName: 'prod-to-staging-gdpr-v1',
  policyVersion: 1,
  policyDirty: false,
  savingPolicy: false,
  saveStatusMessage: null,

  nodes: initialNodes,
  edges: initialEdges,
  previewTableId: null,

  driftReport: null,
  checkingDrift: false,

  runsDrawerOpen: false,
  recentRuns: [],
  loadingRuns: false,

  isRunningSync: false,
  liveProgress: null,
  wsError: null,

  updateColumnStrategy: (tableId, columnName, strategy) =>
    set((state) => ({
      policyDirty: true,
      saveStatusMessage: null,
      nodes: state.nodes.map((node) => {
        if (node.id !== tableId) return node;
        return {
          ...node,
          data: {
            ...node.data,
            columns: node.data.columns.map((col) =>
              col.name === columnName
                ? { ...col, strategy, isUnmapped: false }
                : col
            ),
          },
        };
      }),
    })),

  updateColumnDomain: (tableId, columnName, domain) =>
    set((state) => ({
      policyDirty: true,
      saveStatusMessage: null,
      nodes: state.nodes.map((node) => {
        if (node.id !== tableId) return node;
        return {
          ...node,
          data: {
            ...node.data,
            columns: node.data.columns.map((col) =>
              col.name === columnName
                ? { ...col, deterministicDomain: domain, isUnmapped: false }
                : col
            ),
          },
        };
      }),
    })),

  openPreview: (tableId) => set({ previewTableId: tableId }),
  closePreview: () => set({ previewTableId: null }),
  toggleRunsDrawer: (open) =>
    set((s) => ({ runsDrawerOpen: open ?? !s.runsDrawerOpen })),

  loadActivePolicy: async () => {
    try {
      const res = await fetch(`${GOVERNANCE_URL}/api/v1/governance/policies/active`);
      if (!res.ok) return;
      const policy: BackendPolicy = await res.json();

      set((state) => ({
        policyId: policy.id,
        policyName: policy.name,
        policyVersion: policy.version,
        policyDirty: false,
        nodes: state.nodes.map((node) => {
          const tableRules = policy.rulesJson?.[node.id];
          if (!tableRules) return node;

          const existingNames = new Set(node.data.columns.map((c) => c.name));
          const updatedCols = node.data.columns.map((col) => {
            const saved = tableRules[col.name];
            if (!saved) return col;
            return {
              ...col,
              isUnmapped: false,
              strategy: saved.strategy ?? col.strategy,
              deterministicDomain:
                saved.deterministicDomain ?? col.deterministicDomain,
              preservePrefix: saved.preservePrefix ?? col.preservePrefix,
              preserveSuffix: saved.preserveSuffix ?? col.preserveSuffix,
            };
          });

          // Append any newly saved columns that were mapped from schema drift
          for (const [colName, saved] of Object.entries(tableRules)) {
            if (!existingNames.has(colName)) {
              updatedCols.push({
                name: colName,
                dataType: 'varchar',
                detectedPii: (saved.semanticType as never) || 'NONE',
                piiConfidence: 0.96,
                isUnmapped: false,
                strategy: saved.strategy,
                deterministicDomain: saved.deterministicDomain,
                preservePrefix: saved.preservePrefix,
                preserveSuffix: saved.preserveSuffix,
              });
            }
          }

          return {
            ...node,
            data: {
              ...node.data,
              columns: updatedCols,
            },
          };
        }),
      }));
    } catch {
      // Retain local default ER canvas when governance-core is offline
    }
  },

  checkSchemaDrift: async () => {
    set({ checkingDrift: true });
    try {
      const res = await fetch(
        `${GOVERNANCE_URL}/api/v1/governance/policies/active/drift?strictDriftBlock=true`
      );
      if (!res.ok) {
        set({ checkingDrift: false });
        return;
      }
      const report: PolicyDriftInspectionReport = await res.json();

      // Merge any unmapped live source-db columns onto the React Flow table nodes
      set((state) => {
        const unmappedByTable = new Map<string, UnmappedColumnDrift[]>();
        for (const u of report.unmappedColumns) {
          const list = unmappedByTable.get(u.tableId) ?? [];
          list.push(u);
          unmappedByTable.set(u.tableId, list);
        }

        const nextNodes = state.nodes.map((node) => {
          const tableDrifts = unmappedByTable.get(node.id) ?? [];
          const driftMap = new Map(tableDrifts.map((d) => [d.columnName, d]));

          // Update existing columns or remove stale unmapped columns that no longer exist
          const cols = node.data.columns.map((c) => {
            const d = driftMap.get(c.name);
            if (d) {
              driftMap.delete(c.name);
              return {
                ...c,
                dataType: d.dataType,
                detectedPii: d.detectedPii,
                piiConfidence: d.piiConfidence,
                riskLevel: d.riskLevel,
                isUnmapped: true,
                strategy: d.suggestedStrategy,
                deterministicDomain: d.suggestedDomain,
                preservePrefix: d.suggestedPreservePrefix,
                preserveSuffix: d.suggestedPreserveSuffix,
              };
            }
            return c;
          });

          // Append brand-new unmapped columns discovered in source-db
          for (const d of driftMap.values()) {
            cols.push({
              name: d.columnName,
              dataType: d.dataType,
              detectedPii: d.detectedPii,
              piiConfidence: d.piiConfidence,
              riskLevel: d.riskLevel,
              isUnmapped: true,
              strategy: d.suggestedStrategy,
              deterministicDomain: d.suggestedDomain,
              preservePrefix: d.suggestedPreservePrefix,
              preserveSuffix: d.suggestedPreserveSuffix,
            });
          }

          return {
            ...node,
            data: {
              ...node.data,
              columns: cols,
            },
          };
        });

        return {
          driftReport: report,
          checkingDrift: false,
          nodes: nextNodes,
        };
      });
    } catch {
      set({ checkingDrift: false });
    }
  },

  quickMapDriftColumn: async (drift, strategy, domain) => {
    set((state) => ({
      nodes: state.nodes.map((node) => {
        if (node.id !== drift.tableId) return node;
        const exists = node.data.columns.some((c) => c.name === drift.columnName);
        const updatedCols = exists
          ? node.data.columns.map((col) =>
              col.name === drift.columnName
                ? {
                    ...col,
                    isUnmapped: false,
                    strategy,
                    deterministicDomain: domain ?? drift.suggestedDomain,
                    preservePrefix: drift.suggestedPreservePrefix,
                    preserveSuffix: drift.suggestedPreserveSuffix,
                  }
                : col
            )
          : [
              ...node.data.columns,
              {
                name: drift.columnName,
                dataType: drift.dataType,
                detectedPii: drift.detectedPii,
                piiConfidence: drift.piiConfidence,
                riskLevel: drift.riskLevel,
                isUnmapped: false,
                strategy,
                deterministicDomain: domain ?? drift.suggestedDomain,
                preservePrefix: drift.suggestedPreservePrefix,
                preserveSuffix: drift.suggestedPreserveSuffix,
              },
            ];
        return {
          ...node,
          data: { ...node.data, columns: updatedCols },
        };
      }),
    }));

    await get().savePolicyRules();
    await get().checkSchemaDrift();
  },

  quickMapAllDriftColumns: async () => {
    const report = get().driftReport;
    if (!report || report.unmappedColumns.length === 0) return;

    set((state) => ({
      nodes: state.nodes.map((node) => ({
        ...node,
        data: {
          ...node.data,
          columns: node.data.columns.map((col) =>
            col.isUnmapped ? { ...col, isUnmapped: false } : col
          ),
        },
      })),
    }));

    await get().savePolicyRules();
    await get().checkSchemaDrift();
  },

  savePolicyRules: async () => {
    const { policyId, nodes } = get();
    set({ savingPolicy: true, saveStatusMessage: null });

    const rulesJson: BackendPolicy['rulesJson'] = {};
    for (const node of nodes) {
      rulesJson[node.id] = {};
      for (const col of node.data.columns) {
        // Only persist mapped columns so unmapped columns remain flagged until explicitly mapped
        if (col.isUnmapped) continue;
        rulesJson[node.id][col.name] = {
          strategy: col.strategy,
          semanticType: col.detectedPii,
          deterministicDomain: col.deterministicDomain ?? '',
          preservePrefix: col.preservePrefix ?? 0,
          preserveSuffix: col.preserveSuffix ?? 0,
        };
      }
    }

    try {
      const res = await fetch(
        `${GOVERNANCE_URL}/api/v1/governance/policies/${policyId}/rules`,
        {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ rulesJson }),
        }
      );
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }
      set({
        savingPolicy: false,
        policyDirty: false,
        saveStatusMessage: 'Policy rules persisted to Governance Core',
      });
      await get().checkSchemaDrift();
    } catch (err) {
      set({
        savingPolicy: false,
        saveStatusMessage: `Save failed: ${(err as Error).message}`,
      });
    }
  },

  fetchRecentRuns: async () => {
    set({ loadingRuns: true });
    try {
      const res = await fetch(`${GOVERNANCE_URL}/api/v1/governance/runs`);
      if (res.ok) {
        const data: SyncRunResponse[] = await res.json();
        set({ recentRuns: data, loadingRuns: false });
        return;
      }
    } catch {
      // Ignore network errors while offline
    }
    set({ loadingRuns: false });
  },

  triggerSyncRun: async () => {
    const { policyName, nodes, policyDirty, savePolicyRules, fetchRecentRuns } = get();
    if (policyDirty) {
      await savePolicyRules();
    }

    if (activeSocket) {
      activeSocket.close();
      activeSocket = null;
    }

    set({ isRunningSync: true, wsError: null, liveProgress: null });

    const payload = {
      version: '1.0',
      org_id: '00000000-0000-0000-0000-000000000001',
      policy_id: policyName,
      frameworks: ['GDPR', 'NDPR', 'PCI_DSS'],
      source: { engine: 'postgresql' },
      target: { engine: 'postgresql' },
      runtime: { channel_capacity: 512, worker_concurrency: 4, strict_drift_gate: true },
      tables: nodes.map((n) => ({
        schema: n.data.schemaName,
        name: n.data.tableName,
        truncate_target: true,
        // Omit unmapped columns from execution request so Rust stream-engine enforces fail-closed drift gate
        columns: n.data.columns
          .filter((c) => !c.isUnmapped)
          .map((c) => ({
            name: c.name,
            strategy: c.strategy,
            semantic_type: c.detectedPii === 'NONE' ? '' : c.detectedPii,
            deterministic_domain: c.deterministicDomain ?? '',
            preserve_prefix: c.preservePrefix ?? 0,
            preserve_suffix: c.preserveSuffix ?? 0,
          })),
      })),
    };

    try {
      const res = await fetch(`${ORCHESTRATOR_URL}/api/v1/jobs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (!res.ok) {
        throw new Error(`Orchestrator rejected job (HTTP ${res.status})`);
      }
      const { jobId }: { jobId: string } = await res.json();

      const wsBase = ORCHESTRATOR_URL.replace(/^http/i, 'ws');
      const socket = new WebSocket(`${wsBase}/ws/jobs/${jobId}`);
      activeSocket = socket;

      socket.onmessage = (evt) => {
        if (activeSocket !== socket) return;
        try {
          const progress: LiveProgressEvent = JSON.parse(evt.data);
          const done =
            progress.phase === 'COMPLETED' ||
            progress.phase === 'FAILED' ||
            progress.phase === 'CANCELLED' ||
            progress.phase === 'BLOCKED_DRIFT';

          set({
            liveProgress: progress,
            isRunningSync: !done,
            wsError: progress.errorDetail || null,
          });

          if (done) {
            socket.close();
            void fetchRecentRuns();
          }
        } catch {
          // Ignore malformed frame
        }
      };

      socket.onerror = () => {
        if (activeSocket !== socket) return;
        set({
          wsError: 'WebSocket telemetry connection error',
          isRunningSync: false,
        });
      };

      socket.onclose = () => {
        if (activeSocket !== socket) return;
        if (get().isRunningSync) {
          set({ isRunningSync: false });
          void fetchRecentRuns();
        }
      };
    } catch (err) {
      set({
        wsError: (err as Error).message,
        isRunningSync: false,
      });
    }
  },

  getMockAnonymizedPreview: (tableId) => {
    const node = get().nodes.find((n) => n.id === tableId);
    if (!node) return [];

    return Array.from({ length: 10 }, (_, idx) => {
      const values: Record<string, string | null> = {};
      for (const col of node.data.columns) {
        if (col.strategy === 'NULLIFY') {
          values[col.name] = null;
        } else if (col.strategy === 'PARTIAL_MASK') {
          values[col.name] =
            col.detectedPii === 'CREDIT_CARD'
              ? `****-****-****-${1042 + idx}`
              : col.detectedPii === 'IP_ADDRESS'
              ? `102.********`
              : `a***@example.test`;
        } else if (col.strategy === 'DETERMINISTIC_FAKE') {
          const fakeMap: Record<string, string> = {
            EMAIL: `jordan.blake.${(idx + 10).toString(16)}a4@example.test`,
            FULL_NAME: ['Jordan Blake', 'Maya Chen', 'Tobi Adeyemi', 'Liam Patel', 'Nora Berg', 'Amara Osei', 'Devon Ruiz', 'Hana Sato', 'Owen Brooks', 'Zara Mensah'][idx],
            PHONE: `+1-555-01${10 + idx}`,
            NATIONAL_ID: `SYN-842-1${idx}-90${10 + idx}`,
            STREET_ADDRESS: `${120 + idx * 7} Cedar Grove Ave, Staging City`,
            DATE_OF_BIRTH: `199${idx % 9}-0${(idx % 9) + 1}-1${idx}`,
            CREDIT_CARD: `4242-8190-3342-${1010 + idx}`,
          };
          values[col.name] = fakeMap[col.detectedPii] ?? `syn_val_${idx + 1}`;
        } else if (col.strategy === 'SHUFFLE') {
          values[col.name] = `[shuffled-window #${((idx + 3) % 10) + 1}]`;
        } else {
          values[col.name] =
            col.isPrimaryKey || col.isForeignKey
              ? String(idx + 1)
              : `${col.name}_${idx + 1}`;
        }
      }
      return { rowIndex: idx + 1, values };
    });
  },
}));
