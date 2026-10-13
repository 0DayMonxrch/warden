package rules

import (
	"testing"

	"github.com/0DayMonxrch/warden/pkg/parser/compose"
)

func TestRule005ResourceLimits(t *testing.T) {
	yaml := `services:
  nolimits:
    image: alpine
  deploylimits:
    image: alpine
    deploy:
      resources:
        limits:
          cpus: "0.5"
          memory: "256M"
  legacylimits:
    image: alpine
    cpus: "1.0"
    mem_limit: "512M"
`
	parsed, err := compose.ParseBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx := &ScanContext{
		FilePath:   "docker-compose.yml",
		TargetType: TargetCompose,
		Compose:    parsed,
	}

	rule := &Rule005ResourceLimits{}
	findings, err := rule.Evaluate(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Only nolimits should trigger
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].RuleID != "RULE-005" {
		t.Errorf("expected RULE-005, got %s", findings[0].RuleID)
	}
	if findings[0].Severity != SeverityHigh {
		t.Errorf("expected HIGH severity, got %s", findings[0].Severity)
	}
}
