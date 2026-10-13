package rules

import (
	"testing"

	"github.com/0DayMonxrch/warden/pkg/parser/compose"
)

func TestRule001DockerSock(t *testing.T) {
	vulnerableYaml := `version: "3.8"
services:
  agent:
    image: monitor:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
`
	parsed, err := compose.ParseBytes([]byte(vulnerableYaml))
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	ctx := &ScanContext{
		FilePath:   "docker-compose.yml",
		TargetType: TargetCompose,
		Compose:    parsed,
	}

	rule := &Rule001DockerSock{}
	findings, err := rule.Evaluate(ctx)
	if err != nil {
		t.Fatalf("unexpected evaluate error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].RuleID != "RULE-001" {
		t.Errorf("expected RULE-001, got %s", findings[0].RuleID)
	}
	if findings[0].Severity != SeverityCritical {
		t.Errorf("expected CRITICAL severity, got %s", findings[0].Severity)
	}
}
