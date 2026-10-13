package rules

import (
	"strings"

	"github.com/0DayMonxrch/warden/pkg/parser/compose"
	"github.com/0DayMonxrch/warden/pkg/parser/dockerfile"
)

// Severity represents the criticality level of a rule violation.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

// Level returns a numeric weight for comparison (higher = more critical).
func (s Severity) Level() int {
	switch strings.ToUpper(string(s)) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

// MeetsThreshold returns true if the severity is at or above the threshold.
func (s Severity) MeetsThreshold(threshold Severity) bool {
	return s.Level() >= threshold.Level()
}

// TargetType identifies the kind of file being analyzed.
type TargetType string

const (
	TargetDockerfile TargetType = "Dockerfile"
	TargetCompose    TargetType = "docker-compose.yml"
)

// ScanContext encapsulates the parsed state and metadata of the target file.
type ScanContext struct {
	FilePath   string
	TargetType TargetType
	Dockerfile *dockerfile.ParsedDockerfile
	Compose    *compose.ParsedCompose
}

// Finding represents a single misconfiguration detected by a rule.
type Finding struct {
	RuleID       string   `json:"ruleId"`
	RuleName     string   `json:"ruleName"`
	Severity     Severity `json:"severity"`
	TargetFile   string   `json:"targetFile"`
	Line         int      `json:"line,omitempty"`
	EndLine      int      `json:"endLine,omitempty"`
	Message      string   `json:"message"`
	Mitigation   string   `json:"mitigation"`
	AttackVector string   `json:"attackVector,omitempty"`
}

// Rule defines the interface for static security checks in Warden.
type Rule interface {
	ID() string
	Name() string
	Severity() Severity
	Description() string
	Mitigation() string
	AttackVector() string
	Targets() []TargetType
	Evaluate(ctx *ScanContext) ([]Finding, error)
}
