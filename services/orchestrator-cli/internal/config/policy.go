package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// PolicyFile defines the declarative YAML schema consumed by `sanitizedb run --config policy.yaml`
// inside CI/CD runners (GitHub Actions, GitLab CI) or scheduled cron jobs.
type PolicyFile struct {
	Version    string        `yaml:"version" json:"version"`
	OrgID      string        `yaml:"org_id" json:"org_id"`
	PolicyID   string        `yaml:"policy_id" json:"policy_id"`
	Frameworks []string      `yaml:"frameworks" json:"frameworks"`
	Source     EndpointRef   `yaml:"source" json:"source"`
	Target     EndpointRef   `yaml:"target" json:"target"`
	Runtime    RuntimeConfig `yaml:"runtime" json:"runtime"`
	Tables     []TableRule   `yaml:"tables" json:"tables"`
}

type EndpointRef struct {
	Engine          string `yaml:"engine" json:"engine"`                       // postgresql | mysql
	VaultSecretPath string `yaml:"vault_secret_path" json:"vault_secret_path"` // e.g. secret/data/prod/ro
	EnvDSN          string `yaml:"env_dsn" json:"env_dsn"`                     // CI/CD secret env var name (never raw DSN!)
}

type RuntimeConfig struct {
	ChannelCapacity   uint32 `yaml:"channel_capacity" json:"channel_capacity"`
	WorkerConcurrency uint32 `yaml:"worker_concurrency" json:"worker_concurrency"`
	StrictDriftGate   bool   `yaml:"strict_drift_gate" json:"strict_drift_gate"`
}

type TableRule struct {
	Schema         string       `yaml:"schema" json:"schema"`
	Name           string       `yaml:"name" json:"name"`
	TruncateTarget bool         `yaml:"truncate_target" json:"truncate_target"`
	Columns        []ColumnRule `yaml:"columns" json:"columns"`
}

type ColumnRule struct {
	Name                string `yaml:"name" json:"name"`
	Strategy            string `yaml:"strategy" json:"strategy"` // DETERMINISTIC_FAKE | NULLIFY | PARTIAL_MASK | SHUFFLE | PASS_THROUGH
	SemanticType        string `yaml:"semantic_type,omitempty" json:"semantic_type,omitempty"`
	DeterministicDomain string `yaml:"deterministic_domain,omitempty" json:"deterministic_domain,omitempty"`
	PreservePrefix      uint32 `yaml:"preserve_prefix,omitempty" json:"preserve_prefix,omitempty"`
	PreserveSuffix      uint32 `yaml:"preserve_suffix,omitempty" json:"preserve_suffix,omitempty"`
}

func LoadPolicyFile(path string) (*PolicyFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file %s: %w", path, err)
	}
	var p PolicyFile
	if err := yaml.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("parse policy yaml: %w", err)
	}
	if p.Runtime.ChannelCapacity == 0 {
		p.Runtime.ChannelCapacity = 512
	}
	if p.Runtime.WorkerConcurrency == 0 {
		p.Runtime.WorkerConcurrency = 4
	}
	return &p, nil
}
