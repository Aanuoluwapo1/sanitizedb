export type MaskingStrategy =
  | 'DETERMINISTIC_FAKE'
  | 'NULLIFY'
  | 'PARTIAL_MASK'
  | 'SHUFFLE'
  | 'PASS_THROUGH';

export type PiiCategory =
  | 'NONE'
  | 'EMAIL'
  | 'PHONE'
  | 'CREDIT_CARD'
  | 'NATIONAL_ID'
  | 'IP_ADDRESS'
  | 'FULL_NAME'
  | 'STREET_ADDRESS'
  | 'DATE_OF_BIRTH';

export type PiiRiskLevel = 'HIGH' | 'MEDIUM' | 'LOW';

export interface ColumnConfig {
  name: string;
  dataType: string;
  isPrimaryKey?: boolean;
  isForeignKey?: boolean;
  detectedPii: PiiCategory;
  piiConfidence: number; // 0.0 - 1.0
  riskLevel?: PiiRiskLevel;
  isUnmapped?: boolean;
  strategy: MaskingStrategy;
  deterministicDomain?: string;
  preservePrefix?: number;
  preserveSuffix?: number;
}

export interface TableNodeData extends Record<string, unknown> {
  tableId: string;
  schemaName: string;
  tableName: string;
  estimatedRows: number;
  columns: ColumnConfig[];
}

export interface PreviewRow {
  rowIndex: number;
  values: Record<string, string | null>;
}

export interface UnmappedColumnDrift {
  tableId: string;
  schemaName: string;
  tableName: string;
  columnName: string;
  dataType: string;
  riskLevel: PiiRiskLevel;
  detectedPii: PiiCategory;
  piiConfidence: number;
  matchedPattern: string;
  reason: string;
  suggestedStrategy: MaskingStrategy;
  suggestedDomain: string;
  suggestedPreservePrefix: number;
  suggestedPreserveSuffix: number;
}

export interface PolicyDriftInspectionReport {
  policyId: string;
  policyName: string;
  policyVersion: number;
  schemaFingerprintSha256: string;
  driftDetected: boolean;
  strictDriftBlock: boolean;
  syncBlocked: boolean;
  highRiskCount: number;
  mediumRiskCount: number;
  lowRiskCount: number;
  unmappedColumns: UnmappedColumnDrift[];
  inspectedAt: string;
}

export interface TableProgressEvent {
  qualifiedName: string;
  rowsProcessed: number;
  estimatedTotalRows: number;
  durationMs: number;
  completed: boolean;
}

export interface LiveProgressEvent {
  jobId: string;
  phase: string;
  totalRowsProcessed: number;
  totalBytesStreamed: number;
  rowsPerSecond: number;
  etaSeconds: number;
  durationMs: number;
  workerRssMemoryMb: number;
  activeChannelDepth: number;
  tables: TableProgressEvent[];
  saltCommitment?: string;
  certificateSerial?: string;
  errorDetail?: string;
  emittedAt?: string;
}

export interface AuditCertificateRecord {
  id: string;
  syncJobId: string;
  policyId: string;
  policyVersion: number;
  certificateSerial: string;
  payloadSha256: string;
  previousCertHash: string;
  signatureAlgorithm: string;
  signatureBase64: string;
  signingKeyId: string;
  issuedAt: string;
  certificatePayload: Record<string, unknown>;
}

export interface SyncJobRecord {
  id: string;
  orgId: string;
  policyId: string;
  status: string;
  triggerSource: string;
  workerNodeId?: string;
  saltCommitmentSha256: string;
  totalTables: number;
  completedTables: number;
  rowsProcessed: number;
  bytesStreamed: number;
  avgRowsPerSec: number;
  schemaDriftDetected?: boolean;
  errorMessage?: string;
  startedAt?: string;
  completedAt?: string;
  createdAt: string;
  driftSummaryJson?: {
    durationMs?: number;
    tables?: TableProgressEvent[];
  };
}

export interface SyncRunResponse {
  syncJob: SyncJobRecord;
  certificate: AuditCertificateRecord | null;
}

export const STRATEGY_LABELS: Record<MaskingStrategy, string> = {
  DETERMINISTIC_FAKE: 'Deterministic Fake',
  NULLIFY: 'Nullify',
  PARTIAL_MASK: 'Partial Mask',
  SHUFFLE: 'Shuffle',
  PASS_THROUGH: 'Pass-through',
};
