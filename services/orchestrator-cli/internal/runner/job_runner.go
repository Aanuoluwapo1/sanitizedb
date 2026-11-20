package runner

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/sanitizedb/sanitizedb/services/orchestrator-cli/internal/config"
	"github.com/sanitizedb/sanitizedb/services/orchestrator-cli/internal/ws"
)

type SecretResolver interface {
	ResolveDSN(ctx context.Context, ref config.EndpointRef) (string, error)
}

type InspectedColumn struct {
	Name            string  `json:"name"`
	DataType        string  `json:"dataType"`
	IsNullable      bool    `json:"isNullable"`
	IsPrimaryKey    bool    `json:"isPrimaryKey"`
	DetectedPii     string  `json:"detectedPii"`
	PiiConfidence   float64 `json:"piiConfidence"`
	RiskLevel       string  `json:"riskLevel"`
	MatchedPattern  string  `json:"matchedPattern"`
	DetectionReason string  `json:"detectionReason"`
}

type InspectedTable struct {
	SchemaName string            `json:"schemaName"`
	TableName  string            `json:"tableName"`
	Columns    []InspectedColumn `json:"columns"`
}

type InspectedSchema struct {
	SchemaFingerprintSha256 string           `json:"schemaFingerprintSha256"`
	Tables                  []InspectedTable `json:"tables"`
}

type SyncRunReport struct {
	JobID                  string
	OrgID                  string
	PolicyID               string
	Status                 string // SUCCEEDED | FAILED | CANCELLED | BLOCKED_DRIFT
	TriggerSource          string
	TriggeredBy            string
	WorkerNodeID           string
	EngineVersion          string
	SaltCommitmentSHA256   string
	TotalRowsMasked        uint64
	TotalBytesStreamed     uint64
	DurationMs             uint64
	AvgRowsPerSec          float64
	ZeroDiskWritesVerified bool
	SchemaDriftDetected    bool
	Tables                 []ws.TableProgress
	ErrorMessage           string
	StartedAt              time.Time
	CompletedAt            time.Time
}

// GovernanceGate records completed/failed runs, syncs active policy rules, and mints signed compliance certificates.
type GovernanceGate interface {
	RecordSyncRun(ctx context.Context, report SyncRunReport) (string, error)
	FetchActivePolicyRules(ctx context.Context) (map[string]map[string]config.ColumnRule, error)
}

// StreamEngineClient abstracts the gRPC stream to the Rust Stream Engine (`stream_engine.proto`).
type StreamEngineClient interface {
	InspectSchema(ctx context.Context, sourceDSN string) (InspectedSchema, error)
	ExecuteJob(ctx context.Context, req ExecuteJobParams, onProgress func(ws.ProgressEvent)) (RunAttestation, error)
}

type ExecuteJobParams struct {
	JobID            string
	Policy           *config.PolicyFile
	SourceDSN        string
	TargetDSN        string
	EphemeralJobSalt []byte
}

type RunAttestation struct {
	EngineVersion          string
	SaltCommitmentSHA256   string
	TotalRowsMasked        uint64
	TotalBytesStreamed     uint64
	DurationMs             uint64
	AvgRowsPerSec          float64
	ZeroDiskWritesVerified bool
	Tables                 []ws.TableProgress
	CompletedAt            time.Time
}

type RunResult struct {
	JobID             string
	Attestation       RunAttestation
	CertificateSerial string
}

type JobRunner struct {
	secrets     SecretResolver
	governance  GovernanceGate
	engine      StreamEngineClient
	broadcaster *ws.ProgressBroadcaster
	logger      *slog.Logger
	workerAddr  string

	mu         sync.Mutex
	activeJobs map[string]context.CancelFunc
}

func NewJobRunner(
	secrets SecretResolver,
	governance GovernanceGate,
	engine StreamEngineClient,
	broadcaster *ws.ProgressBroadcaster,
	logger *slog.Logger,
	workerAddr string,
) *JobRunner {
	return &JobRunner{
		secrets:     secrets,
		governance:  governance,
		engine:      engine,
		broadcaster: broadcaster,
		logger:      logger,
		workerAddr:  workerAddr,
		activeJobs:  make(map[string]context.CancelFunc),
	}
}

func (r *JobRunner) InspectSourceSchema(ctx context.Context, ref config.EndpointRef) (InspectedSchema, error) {
	if ref.EnvDSN == "" && ref.VaultSecretPath == "" {
		ref.EnvDSN = "SANITIZEDB_SOURCE_DSN"
	}
	dsn, err := r.secrets.ResolveDSN(ctx, ref)
	if err != nil {
		return InspectedSchema{}, err
	}
	return r.engine.InspectSchema(ctx, dsn)
}

func (r *JobRunner) Run(ctx context.Context, policy *config.PolicyFile) (RunResult, error) {
	return r.RunWithID(ctx, uuid.NewString(), policy, "CLI_CI")
}

// RunWithID executes an end-to-end zero-leak anonymization pipeline under a pre-allocated jobID.
func (r *JobRunner) RunWithID(
	ctx context.Context,
	jobID string,
	policy *config.PolicyFile,
	triggerSource string,
) (RunResult, error) {
	startedAt := time.Now().UTC()
	jobCtx, cancel := context.WithCancel(ctx)

	r.mu.Lock()
	r.activeJobs[jobID] = cancel
	r.mu.Unlock()

	defer func() {
		cancel()
		r.mu.Lock()
		delete(r.activeJobs, jobID)
		r.mu.Unlock()
	}()

	r.broadcaster.Publish(ws.ProgressEvent{
		JobID: jobID,
		Phase: "VALIDATING",
	})

	// Overlay any newly mapped rules saved in Governance Core so CLI & Web Console stay in sync.
	if r.governance != nil && triggerSource == "CLI_CI" {
		if activeRules, err := r.governance.FetchActivePolicyRules(jobCtx); err == nil && len(activeRules) > 0 {
			mergeGovernanceRulesIntoPolicy(policy, activeRules)
		}
	}

	// Step 1: Generate ephemeral 256-bit per-job HMAC salt (scrubbed in defer)
	jobSalt := make([]byte, 32)
	if _, err := rand.Read(jobSalt); err != nil {
		return RunResult{JobID: jobID}, fmt.Errorf("generate ephemeral job salt: %w", err)
	}
	defer func() {
		for i := range jobSalt {
			jobSalt[i] = 0
		}
	}()
	saltHash := sha256.Sum256(jobSalt)
	saltCommitment := hex.EncodeToString(saltHash[:])

	r.logger.Info("starting zero-leak sanitization job",
		"job_id", jobID,
		"policy_id", policy.PolicyID,
		"trigger_source", triggerSource,
		"salt_commitment", saltCommitment,
	)

	// Step 2: Resolve short-lived credentials from Vault/KMS or server-side env
	sourceDSN, err := r.secrets.ResolveDSN(jobCtx, policy.Source)
	if err != nil {
		r.reportFailure(jobID, policy, triggerSource, saltCommitment, startedAt, err)
		return RunResult{JobID: jobID}, fmt.Errorf("resolve source secret: %w", err)
	}
	targetDSN, err := r.secrets.ResolveDSN(jobCtx, policy.Target)
	if err != nil {
		r.reportFailure(jobID, policy, triggerSource, saltCommitment, startedAt, err)
		return RunResult{JobID: jobID}, fmt.Errorf("resolve target secret: %w", err)
	}

	// Step 3: Execute streaming anonymization over gRPC to Rust Stream Engine
	attestation, err := r.engine.ExecuteJob(jobCtx, ExecuteJobParams{
		JobID:            jobID,
		Policy:           policy,
		SourceDSN:        sourceDSN,
		TargetDSN:        targetDSN,
		EphemeralJobSalt: jobSalt,
	}, func(ev ws.ProgressEvent) {
		ev.JobID = jobID
		ev.SaltCommitment = saltCommitment
		r.broadcaster.Publish(ev)
	})
	if err != nil {
		r.reportFailure(jobID, policy, triggerSource, saltCommitment, startedAt, err)
		return RunResult{JobID: jobID}, err
	}

	if attestation.SaltCommitmentSHA256 == "" {
		attestation.SaltCommitmentSHA256 = saltCommitment
	}
	if attestation.DurationMs == 0 {
		attestation.DurationMs = uint64(time.Since(startedAt).Milliseconds())
	}

	// Step 4: Record sync job & mint signed immutable compliance certificate in Governance Core
	certSerial := ""
	if r.governance != nil {
		reportCtx, reportCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer reportCancel()
		certSerial, err = r.governance.RecordSyncRun(reportCtx, SyncRunReport{
			JobID:                  jobID,
			OrgID:                  policy.OrgID,
			PolicyID:               policy.PolicyID,
			Status:                 "SUCCEEDED",
			TriggerSource:          triggerSource,
			TriggeredBy:            "orchestrator",
			WorkerNodeID:           r.workerAddr,
			EngineVersion:          attestation.EngineVersion,
			SaltCommitmentSHA256:   attestation.SaltCommitmentSHA256,
			TotalRowsMasked:        attestation.TotalRowsMasked,
			TotalBytesStreamed:     attestation.TotalBytesStreamed,
			DurationMs:             attestation.DurationMs,
			AvgRowsPerSec:          attestation.AvgRowsPerSec,
			ZeroDiskWritesVerified: attestation.ZeroDiskWritesVerified,
			Tables:                 attestation.Tables,
			StartedAt:              startedAt,
			CompletedAt:            time.Now().UTC(),
		})
		if err != nil {
			r.logger.Error("failed to record sync run in governance-core", "job_id", jobID, "err", err)
		}
	}

	r.broadcaster.Publish(ws.ProgressEvent{
		JobID:              jobID,
		Phase:              "COMPLETED",
		TotalRowsProcessed: attestation.TotalRowsMasked,
		TotalBytesStreamed: attestation.TotalBytesStreamed,
		RowsPerSecond:      attestation.AvgRowsPerSec,
		DurationMs:         attestation.DurationMs,
		Tables:             attestation.Tables,
		SaltCommitment:     attestation.SaltCommitmentSHA256,
		CertificateSerial:  certSerial,
	})

	return RunResult{
		JobID:             jobID,
		Attestation:       attestation,
		CertificateSerial: certSerial,
	}, nil
}

func mergeGovernanceRulesIntoPolicy(
	policy *config.PolicyFile,
	activeRules map[string]map[string]config.ColumnRule,
) {
	for i := range policy.Tables {
		tbl := &policy.Tables[i]
		fq := tbl.Schema + "." + tbl.Name
		govCols, ok := activeRules[fq]
		if !ok {
			continue
		}
		existing := make(map[string]int, len(tbl.Columns))
		for idx, c := range tbl.Columns {
			existing[c.Name] = idx
		}
		for colName, govRule := range govCols {
			if idx, found := existing[colName]; found {
				tbl.Columns[idx].Strategy = govRule.Strategy
				if govRule.SemanticType != "" {
					tbl.Columns[idx].SemanticType = govRule.SemanticType
				}
				tbl.Columns[idx].DeterministicDomain = govRule.DeterministicDomain
				tbl.Columns[idx].PreservePrefix = govRule.PreservePrefix
				tbl.Columns[idx].PreserveSuffix = govRule.PreserveSuffix
			} else {
				tbl.Columns = append(tbl.Columns, govRule)
			}
		}
	}
}

func (r *JobRunner) reportFailure(
	jobID string,
	policy *config.PolicyFile,
	triggerSource string,
	saltCommitment string,
	startedAt time.Time,
	runErr error,
) {
	status := "FAILED"
	driftDetected := false
	if errors.Is(runErr, context.Canceled) {
		status = "CANCELLED"
	} else if strings.Contains(runErr.Error(), "SCHEMA_DRIFT_BLOCKED") {
		status = "BLOCKED_DRIFT"
		driftDetected = true
	}

	r.broadcaster.Publish(ws.ProgressEvent{
		JobID:          jobID,
		Phase:          status,
		SaltCommitment: saltCommitment,
		DurationMs:     uint64(time.Since(startedAt).Milliseconds()),
		ErrorDetail:    runErr.Error(),
	})

	if r.governance != nil {
		reportCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := r.governance.RecordSyncRun(reportCtx, SyncRunReport{
			JobID:                jobID,
			OrgID:                policy.OrgID,
			PolicyID:             policy.PolicyID,
			Status:               status,
			TriggerSource:        triggerSource,
			TriggeredBy:          "orchestrator",
			WorkerNodeID:         r.workerAddr,
			SaltCommitmentSHA256: saltCommitment,
			DurationMs:           uint64(time.Since(startedAt).Milliseconds()),
			SchemaDriftDetected:  driftDetected,
			ErrorMessage:         runErr.Error(),
			StartedAt:            startedAt,
			CompletedAt:          time.Now().UTC(),
		}); err != nil {
			r.logger.Error("failed to record failed sync run in governance-core", "job_id", jobID, "err", err)
		}
	}
}

func (r *JobRunner) Cancel(jobID string) bool {
	r.mu.Lock()
	cancel, ok := r.activeJobs[jobID]
	r.mu.Unlock()
	if ok {
		cancel()
	}
	return ok
}

type EnvAndVaultSecretResolver struct {
	VaultAddr  string
	VaultToken string
}

func (s *EnvAndVaultSecretResolver) ResolveDSN(_ context.Context, ref config.EndpointRef) (string, error) {
	if ref.EnvDSN != "" {
		if val := os.Getenv(ref.EnvDSN); val != "" {
			return val, nil
		}
		return "", fmt.Errorf("required secret env var %s is unset", ref.EnvDSN)
	}
	if ref.VaultSecretPath != "" {
		return "", fmt.Errorf("vault secret fetch for %s requires active Vault client wiring", ref.VaultSecretPath)
	}
	return "", errors.New("endpoint must specify either vault_secret_path or env_dsn")
}
