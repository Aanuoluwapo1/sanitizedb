package grpcclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	sanitizedbv1 "github.com/sanitizedb/sanitizedb/services/orchestrator-cli/gen/sanitizedb/v1"
	"github.com/sanitizedb/sanitizedb/services/orchestrator-cli/internal/config"
	"github.com/sanitizedb/sanitizedb/services/orchestrator-cli/internal/runner"
	"github.com/sanitizedb/sanitizedb/services/orchestrator-cli/internal/ws"
)

// Client is a live gRPC adapter between the Go Orchestrator and the Rust Stream Engine.
type Client struct {
	conn *grpc.ClientConn
	rpc  sanitizedbv1.StreamEngineServiceClient
}

func Dial(addr string) (*Client, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("dial stream-engine %s: %w", addr, err)
	}
	return &Client{
		conn: conn,
		rpc:  sanitizedbv1.NewStreamEngineServiceClient(conn),
	}, nil
}

func (c *Client) Close() error {
	return c.conn.Close()
}

func (c *Client) InspectSchema(ctx context.Context, sourceDSN string) (runner.InspectedSchema, error) {
	resp, err := c.rpc.InspectSchema(ctx, &sanitizedbv1.InspectSchemaRequest{
		RequestId: "inspect-live",
		Source: &sanitizedbv1.ConnectionEndpoint{
			Engine:       sanitizedbv1.DatabaseEngine_DATABASE_ENGINE_POSTGRESQL,
			EphemeralDsn: sourceDSN,
		},
		IncludeSchemas: []string{"public"},
	})
	if err != nil {
		return runner.InspectedSchema{}, fmt.Errorf("InspectSchema RPC failed: %w", err)
	}

	tables := make([]runner.InspectedTable, 0, len(resp.Tables))
	for _, t := range resp.Tables {
		cols := make([]runner.InspectedColumn, 0, len(t.Columns))
		for _, col := range t.Columns {
			risk := "LOW"
			pattern := "none"
			reason := col.DetectionReason
			parts := strings.SplitN(col.DetectionReason, ":", 3)
			if len(parts) == 3 {
				risk = parts[0]
				pattern = parts[1]
				reason = parts[2]
			}
			cols = append(cols, runner.InspectedColumn{
				Name:            col.Name,
				DataType:        col.DataType,
				IsNullable:      col.IsNullable,
				IsPrimaryKey:    col.IsPrimaryKey,
				DetectedPii:     fromPBPiiCategory(col.DetectedPii),
				PiiConfidence:   float64(col.PiiConfidence),
				RiskLevel:       risk,
				MatchedPattern:  pattern,
				DetectionReason: reason,
			})
		}
		tables = append(tables, runner.InspectedTable{
			SchemaName: t.SchemaName,
			TableName:  t.TableName,
			Columns:    cols,
		})
	}

	return runner.InspectedSchema{
		SchemaFingerprintSha256: resp.SchemaFingerprintSha256,
		Tables:                  tables,
	}, nil
}

func (c *Client) ExecuteJob(
	ctx context.Context,
	req runner.ExecuteJobParams,
	onProgress func(ws.ProgressEvent),
) (runner.RunAttestation, error) {
	pbTables := make([]*sanitizedbv1.TablePolicy, 0, len(req.Policy.Tables))
	for _, t := range req.Policy.Tables {
		rules := make([]*sanitizedbv1.ColumnMaskingRule, 0, len(t.Columns))
		for _, col := range t.Columns {
			rules = append(rules, &sanitizedbv1.ColumnMaskingRule{
				ColumnName:          col.Name,
				Strategy:            toPBStrategy(col.Strategy),
				SemanticType:        toPBPiiCategory(col.SemanticType),
				DeterministicDomain: col.DeterministicDomain,
				PreservePrefixChars: col.PreservePrefix,
				PreserveSuffixChars: col.PreserveSuffix,
				PreserveNulls:       true,
			})
		}
		pbTables = append(pbTables, &sanitizedbv1.TablePolicy{
			SchemaName:               t.Schema,
			TableName:                t.Name,
			TruncateTargetBeforeLoad: t.TruncateTarget,
			ColumnRules:              rules,
		})
	}

	pbReq := &sanitizedbv1.ExecuteJobRequest{
		JobId:            req.JobID,
		OrgId:            req.Policy.OrgID,
		PolicyId:         req.Policy.PolicyID,
		PolicyVersion:    1,
		EphemeralJobSalt: req.EphemeralJobSalt,
		Source: &sanitizedbv1.ConnectionEndpoint{
			Engine:       toPBEngine(req.Policy.Source.Engine),
			EphemeralDsn: req.SourceDSN,
		},
		Target: &sanitizedbv1.ConnectionEndpoint{
			Engine:       toPBEngine(req.Policy.Target.Engine),
			EphemeralDsn: req.TargetDSN,
		},
		Tables:            pbTables,
		ChannelCapacity:   req.Policy.Runtime.ChannelCapacity,
		WorkerConcurrency: req.Policy.Runtime.WorkerConcurrency,
	}

	stream, err := c.rpc.ExecuteSanitizationJob(ctx, pbReq)
	if err != nil {
		return runner.RunAttestation{}, fmt.Errorf("ExecuteSanitizationJob RPC failed: %w", err)
	}

	var finalAttestation runner.RunAttestation
	var completed bool

	for {
		ev, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return runner.RunAttestation{}, fmt.Errorf("stream recv error: %w", err)
		}

		if ev.Phase == sanitizedbv1.JobPhase_JOB_PHASE_FAILED {
			return runner.RunAttestation{}, fmt.Errorf("stream-engine job failed: %s", ev.ErrorDetail)
		}

		tables := make([]ws.TableProgress, 0, len(ev.Tables))
		for _, tp := range ev.Tables {
			tables = append(tables, ws.TableProgress{
				QualifiedName:      tp.QualifiedName,
				RowsProcessed:      tp.RowsProcessed,
				EstimatedTotalRows: tp.EstimatedTotalRows,
				DurationMs:         tp.DurationMs,
				Completed:          tp.Completed,
			})
		}

		if ev.Phase == sanitizedbv1.JobPhase_JOB_PHASE_COMPLETED && ev.Attestation != nil {
			completed = true
			finalAttestation = runner.RunAttestation{
				EngineVersion:          ev.Attestation.EngineVersion,
				SaltCommitmentSHA256:   ev.Attestation.SaltCommitmentSha256,
				TotalRowsMasked:        ev.Attestation.TotalRowsMasked,
				TotalBytesStreamed:     ev.TotalBytesStreamed,
				DurationMs:             ev.Attestation.DurationMs,
				AvgRowsPerSec:          ev.RowsPerSecond,
				ZeroDiskWritesVerified: ev.Attestation.ZeroDiskWritesVerified,
				Tables:                 tables,
				CompletedAt:            time.Now().UTC(),
			}
			continue
		}

		if onProgress != nil {
			onProgress(ws.ProgressEvent{
				JobID:              ev.JobId,
				Phase:              ev.Phase.String(),
				TotalRowsProcessed: ev.TotalRowsProcessed,
				TotalBytesStreamed: ev.TotalBytesStreamed,
				RowsPerSecond:      ev.RowsPerSecond,
				ETASeconds:         ev.EtaSeconds,
				WorkerRSSMemoryMB:  float64(ev.WorkerRssMemoryBytes) / (1024.0 * 1024.0),
				ActiveChannelDepth: ev.ActiveChannelDepth,
				Tables:             tables,
				ErrorDetail:        ev.ErrorDetail,
				EmittedAt:          time.Now().UTC(),
			})
		}
	}

	if !completed {
		return runner.RunAttestation{}, errors.New("stream ended without JOB_PHASE_COMPLETED attestation")
	}
	return finalAttestation, nil
}

func toPBEngine(engine string) sanitizedbv1.DatabaseEngine {
	if strings.EqualFold(engine, "mysql") {
		return sanitizedbv1.DatabaseEngine_DATABASE_ENGINE_MYSQL
	}
	return sanitizedbv1.DatabaseEngine_DATABASE_ENGINE_POSTGRESQL
}

func toPBStrategy(strategy string) sanitizedbv1.MaskingStrategy {
	switch strings.ToUpper(strings.TrimSpace(strategy)) {
	case "DETERMINISTIC_FAKE", "FAKE":
		return sanitizedbv1.MaskingStrategy_MASKING_STRATEGY_DETERMINISTIC_FAKE
	case "PARTIAL_MASK":
		return sanitizedbv1.MaskingStrategy_MASKING_STRATEGY_PARTIAL_MASK
	case "SHUFFLE":
		return sanitizedbv1.MaskingStrategy_MASKING_STRATEGY_SHUFFLE
	case "PASS_THROUGH":
		return sanitizedbv1.MaskingStrategy_MASKING_STRATEGY_PASS_THROUGH
	case "NULLIFY":
		return sanitizedbv1.MaskingStrategy_MASKING_STRATEGY_NULLIFY
	default:
		return sanitizedbv1.MaskingStrategy_MASKING_STRATEGY_UNSPECIFIED
	}
}

func toPBPiiCategory(cat string) sanitizedbv1.PiiCategory {
	switch strings.ToUpper(strings.TrimSpace(cat)) {
	case "EMAIL":
		return sanitizedbv1.PiiCategory_PII_CATEGORY_EMAIL
	case "PHONE":
		return sanitizedbv1.PiiCategory_PII_CATEGORY_PHONE
	case "CREDIT_CARD":
		return sanitizedbv1.PiiCategory_PII_CATEGORY_CREDIT_CARD
	case "NATIONAL_ID":
		return sanitizedbv1.PiiCategory_PII_CATEGORY_NATIONAL_ID
	case "IP_ADDRESS":
		return sanitizedbv1.PiiCategory_PII_CATEGORY_IP_ADDRESS
	case "FULL_NAME":
		return sanitizedbv1.PiiCategory_PII_CATEGORY_FULL_NAME
	case "STREET_ADDRESS":
		return sanitizedbv1.PiiCategory_PII_CATEGORY_STREET_ADDRESS
	case "DATE_OF_BIRTH":
		return sanitizedbv1.PiiCategory_PII_CATEGORY_DATE_OF_BIRTH
	default:
		return sanitizedbv1.PiiCategory_PII_CATEGORY_NONE
	}
}

func fromPBPiiCategory(cat sanitizedbv1.PiiCategory) string {
	switch cat {
	case sanitizedbv1.PiiCategory_PII_CATEGORY_EMAIL:
		return "EMAIL"
	case sanitizedbv1.PiiCategory_PII_CATEGORY_PHONE:
		return "PHONE"
	case sanitizedbv1.PiiCategory_PII_CATEGORY_CREDIT_CARD:
		return "CREDIT_CARD"
	case sanitizedbv1.PiiCategory_PII_CATEGORY_NATIONAL_ID:
		return "NATIONAL_ID"
	case sanitizedbv1.PiiCategory_PII_CATEGORY_IP_ADDRESS:
		return "IP_ADDRESS"
	case sanitizedbv1.PiiCategory_PII_CATEGORY_FULL_NAME:
		return "FULL_NAME"
	case sanitizedbv1.PiiCategory_PII_CATEGORY_STREET_ADDRESS:
		return "STREET_ADDRESS"
	case sanitizedbv1.PiiCategory_PII_CATEGORY_DATE_OF_BIRTH:
		return "DATE_OF_BIRTH"
	default:
		return "NONE"
	}
}

var _ runner.StreamEngineClient = (*Client)(nil)
var _ = config.PolicyFile{}
