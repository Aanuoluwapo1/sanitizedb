package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/sanitizedb/sanitizedb/services/orchestrator-cli/internal/config"
	"github.com/sanitizedb/sanitizedb/services/orchestrator-cli/internal/governance"
	"github.com/sanitizedb/sanitizedb/services/orchestrator-cli/internal/grpcclient"
	"github.com/sanitizedb/sanitizedb/services/orchestrator-cli/internal/runner"
	"github.com/sanitizedb/sanitizedb/services/orchestrator-cli/internal/ws"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	rootCmd := &cobra.Command{
		Use:   "sanitizedb",
		Short: "SanitizeDB Control Plane Orchestrator & CI/CD Anonymization CLI",
	}

	var configPath string
	var engineAddr string
	var governanceURL string
	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Execute a zero-leak staging anonymization pipeline from a declarative policy YAML",
		RunE: func(cmd *cobra.Command, _ []string) error {
			policy, err := config.LoadPolicyFile(configPath)
			if err != nil {
				return err
			}

			engineClient, err := grpcclient.Dial(engineAddr)
			if err != nil {
				return err
			}
			defer engineClient.Close()

			govClient := governance.NewClient(governanceURL, logger)
			broadcaster := ws.NewProgressBroadcaster(logger)
			jr := runner.NewJobRunner(
				&runner.EnvAndVaultSecretResolver{
					VaultAddr:  os.Getenv("VAULT_ADDR"),
					VaultToken: os.Getenv("VAULT_TOKEN"),
				},
				govClient,
				engineClient,
				broadcaster,
				logger,
				engineAddr,
			)

			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			res, err := jr.Run(ctx, policy)
			if err != nil {
				return err
			}

			fmt.Printf("SanitizeDB job %s completed cleanly via %s (%d rows in %dms, zero-disk-leak verified)\n",
				res.JobID, engineAddr, res.Attestation.TotalRowsMasked, res.Attestation.DurationMs)
			fmt.Printf("Salt Commitment (SHA-256): %s\n", res.Attestation.SaltCommitmentSHA256)
			if res.CertificateSerial != "" {
				fmt.Printf("Compliance Certificate:    %s\n", res.CertificateSerial)
			}
			for _, tbl := range res.Attestation.Tables {
				fmt.Printf("  - %-24s %6d rows (%dms)\n", tbl.QualifiedName, tbl.RowsProcessed, tbl.DurationMs)
			}
			return nil
		},
	}
	runCmd.Flags().StringVarP(&configPath, "config", "c", "policy.yaml", "Path to declarative masking policy YAML")
	runCmd.Flags().StringVar(&engineAddr, "engine-addr", envOrDefault("STREAM_ENGINE_GRPC_ADDR", "localhost:50051"), "Rust Stream Engine gRPC address")
	runCmd.Flags().StringVar(&governanceURL, "governance-url", envOrDefault("GOVERNANCE_CORE_URL", "http://governance-core:8081"), "Governance Core HTTP URL")

	var listenAddr string
	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the SanitizeDB Orchestrator HTTP/WebSocket API and job scheduler",
		RunE: func(cmd *cobra.Command, _ []string) error {
			grpcAddr := envOrDefault("STREAM_ENGINE_GRPC_ADDR", "stream-engine:50051")
			govURL := envOrDefault("GOVERNANCE_CORE_URL", "http://governance-core:8081")

			engineClient, err := grpcclient.Dial(grpcAddr)
			if err != nil {
				return err
			}
			defer engineClient.Close()

			govClient := governance.NewClient(govURL, logger)
			broadcaster := ws.NewProgressBroadcaster(logger)
			jr := runner.NewJobRunner(
				&runner.EnvAndVaultSecretResolver{
					VaultAddr:  os.Getenv("VAULT_ADDR"),
					VaultToken: os.Getenv("VAULT_TOKEN"),
				},
				govClient,
				engineClient,
				broadcaster,
				logger,
				grpcAddr,
			)

			mux := http.NewServeMux()
			mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"status":"ok","engine":"` + grpcAddr + `","governance":"` + govURL + `"}`))
			})
			mux.HandleFunc("GET /api/v1/schema/inspect", func(w http.ResponseWriter, r *http.Request) {
				schema, err := jr.InspectSourceSchema(r.Context(), config.EndpointRef{
					Engine: "postgresql",
					EnvDSN: "SANITIZEDB_SOURCE_DSN",
				})
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadGateway)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(schema)
			})
			mux.HandleFunc("GET /ws/jobs/{jobId}", broadcaster.ServeWS)
			mux.HandleFunc("POST /api/v1/jobs", func(w http.ResponseWriter, r *http.Request) {
				var policy config.PolicyFile
				if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
					http.Error(w, "invalid policy payload", http.StatusBadRequest)
					return
				}
				if policy.OrgID == "" {
					policy.OrgID = "00000000-0000-0000-0000-000000000001"
				}
				if policy.PolicyID == "" {
					policy.PolicyID = "prod-to-staging-gdpr-v1"
				}
				if policy.Source.Engine == "" {
					policy.Source.Engine = "postgresql"
				}
				if policy.Source.EnvDSN == "" && policy.Source.VaultSecretPath == "" {
					policy.Source.EnvDSN = "SANITIZEDB_SOURCE_DSN"
				}
				if policy.Target.Engine == "" {
					policy.Target.Engine = "postgresql"
				}
				if policy.Target.EnvDSN == "" && policy.Target.VaultSecretPath == "" {
					policy.Target.EnvDSN = "SANITIZEDB_TARGET_DSN"
				}
				if policy.Runtime.ChannelCapacity == 0 {
					policy.Runtime.ChannelCapacity = 512
				}
				if policy.Runtime.WorkerConcurrency == 0 {
					policy.Runtime.WorkerConcurrency = 4
				}

				jobID := uuid.NewString()
				go func() {
					if _, err := jr.RunWithID(context.Background(), jobID, &policy, "WEB_UI"); err != nil {
						logger.Error("async web job failed", "job_id", jobID, "err", err)
					}
				}()

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusAccepted)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"jobId":  jobID,
					"status": "accepted",
					"wsPath": "/ws/jobs/" + jobID,
				})
			})

			srv := &http.Server{
				Addr:              listenAddr,
				Handler:           withCORS(mux),
				ReadHeaderTimeout: 10 * time.Second,
				IdleTimeout:       120 * time.Second,
			}
			logger.Info("SanitizeDB Orchestrator listening",
				"addr", listenAddr,
				"stream_engine", grpcAddr,
				"governance_core", govURL,
			)
			return srv.ListenAndServe()
		},
	}
	serveCmd.Flags().StringVar(&listenAddr, "addr", envOrDefault("HTTP_ADDR", ":8080"), "HTTP/WebSocket listen address")

	rootCmd.AddCommand(runCmd, serveCmd)
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func envOrDefault(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}
