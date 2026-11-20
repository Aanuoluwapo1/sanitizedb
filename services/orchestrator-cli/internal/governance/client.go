package governance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/sanitizedb/sanitizedb/services/orchestrator-cli/internal/config"
	"github.com/sanitizedb/sanitizedb/services/orchestrator-cli/internal/runner"
)

// Client reports sync run outcomes and reads active policy rules from Java Governance Core.
type Client struct {
	baseURL    string
	httpClient *http.Client
	logger     *slog.Logger
}

func NewClient(baseURL string, logger *slog.Logger) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		logger: logger,
	}
}

type tableRunSummaryPayload struct {
	QualifiedName string `json:"qualifiedName"`
	RowsProcessed uint64 `json:"rowsProcessed"`
	DurationMs    uint64 `json:"durationMs"`
	Completed     bool   `json:"completed"`
}

type recordRunPayload struct {
	JobID                  string                   `json:"jobId"`
	OrgID                  string                   `json:"orgId"`
	PolicyID               string                   `json:"policyId"`
	Status                 string                   `json:"status"`
	TriggerSource          string                   `json:"triggerSource"`
	TriggeredBy            string                   `json:"triggeredBy"`
	WorkerNodeID           string                   `json:"workerNodeId"`
	EngineVersion          string                   `json:"engineVersion"`
	SaltCommitmentSha256   string                   `json:"saltCommitmentSha256"`
	TotalRowsMasked        uint64                   `json:"totalRowsMasked"`
	TotalBytesStreamed     uint64                   `json:"totalBytesStreamed"`
	DurationMs             uint64                   `json:"durationMs"`
	AvgRowsPerSec          float64                  `json:"avgRowsPerSec"`
	ZeroDiskWritesVerified bool                     `json:"zeroDiskWritesVerified"`
	SchemaDriftDetected    bool                     `json:"schemaDriftDetected"`
	Tables                 []tableRunSummaryPayload `json:"tables"`
	ErrorMessage           string                   `json:"errorMessage,omitempty"`
	StartedAt              time.Time                `json:"startedAt"`
	CompletedAt            time.Time                `json:"completedAt"`
}

type recordRunResponse struct {
	Certificate *struct {
		CertificateSerial string `json:"certificateSerial"`
	} `json:"certificate"`
}

type activePolicyResponse struct {
	RulesJson map[string]map[string]struct {
		Strategy            string `json:"strategy"`
		SemanticType        string `json:"semanticType"`
		DeterministicDomain string `json:"deterministicDomain"`
		PreservePrefix      uint32 `json:"preservePrefix"`
		PreserveSuffix      uint32 `json:"preserveSuffix"`
	} `json:"rulesJson"`
}

func (c *Client) FetchActivePolicyRules(ctx context.Context) (map[string]map[string]config.ColumnRule, error) {
	if c.baseURL == "" {
		return nil, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/governance/policies/active", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("governance active policy HTTP %d", resp.StatusCode)
	}
	var parsed activePolicyResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}
	out := make(map[string]map[string]config.ColumnRule, len(parsed.RulesJson))
	for tbl, cols := range parsed.RulesJson {
		out[tbl] = make(map[string]config.ColumnRule, len(cols))
		for colName, spec := range cols {
			out[tbl][colName] = config.ColumnRule{
				Name:                colName,
				Strategy:            spec.Strategy,
				SemanticType:        spec.SemanticType,
				DeterministicDomain: spec.DeterministicDomain,
				PreservePrefix:      spec.PreservePrefix,
				PreserveSuffix:      spec.PreserveSuffix,
			}
		}
	}
	return out, nil
}

func (c *Client) RecordSyncRun(ctx context.Context, report runner.SyncRunReport) (string, error) {
	if c.baseURL == "" {
		return "", nil
	}

	tables := make([]tableRunSummaryPayload, 0, len(report.Tables))
	for _, t := range report.Tables {
		tables = append(tables, tableRunSummaryPayload{
			QualifiedName: t.QualifiedName,
			RowsProcessed: t.RowsProcessed,
			DurationMs:    t.DurationMs,
			Completed:     t.Completed,
		})
	}

	bodyBytes, err := json.Marshal(recordRunPayload{
		JobID:                  report.JobID,
		OrgID:                  report.OrgID,
		PolicyID:               report.PolicyID,
		Status:                 report.Status,
		TriggerSource:          report.TriggerSource,
		TriggeredBy:            report.TriggeredBy,
		WorkerNodeID:           report.WorkerNodeID,
		EngineVersion:          report.EngineVersion,
		SaltCommitmentSha256:   report.SaltCommitmentSHA256,
		TotalRowsMasked:        report.TotalRowsMasked,
		TotalBytesStreamed:     report.TotalBytesStreamed,
		DurationMs:             report.DurationMs,
		AvgRowsPerSec:          report.AvgRowsPerSec,
		ZeroDiskWritesVerified: report.ZeroDiskWritesVerified,
		SchemaDriftDetected:    report.SchemaDriftDetected,
		Tables:                 tables,
		ErrorMessage:           report.ErrorMessage,
		StartedAt:              report.StartedAt,
		CompletedAt:            report.CompletedAt,
	})
	if err != nil {
		return "", fmt.Errorf("marshal governance run report: %w", err)
	}

	endpoint := c.baseURL + "/api/v1/governance/runs"
	backoffs := []time.Duration{200 * time.Millisecond, 600 * time.Millisecond, 1200 * time.Millisecond}

	var lastErr error
	for attempt := 0; attempt < len(backoffs); attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
		if err != nil {
			return "", err
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := c.httpClient.Do(req)
		if err == nil {
			respBody, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()

			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				var parsed recordRunResponse
				if err := json.Unmarshal(respBody, &parsed); err != nil {
					return "", nil
				}
				if parsed.Certificate != nil {
					return parsed.Certificate.CertificateSerial, nil
				}
				return "", nil
			}
			lastErr = fmt.Errorf("governance-core HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
			if resp.StatusCode < 500 {
				return "", lastErr
			}
		} else {
			lastErr = err
		}

		c.logger.Warn("retrying governance-core run recording",
			"attempt", attempt+1,
			"job_id", report.JobID,
			"err", lastErr,
		)
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(backoffs[attempt]):
		}
	}

	return "", fmt.Errorf("governance-core unreachable after retries: %w", lastErr)
}

var _ runner.GovernanceGate = (*Client)(nil)
