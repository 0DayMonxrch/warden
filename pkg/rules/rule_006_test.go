package rules

import (
	"testing"

	"github.com/0DayMonxrch/warden/pkg/parser/compose"
)

func TestRule006WritableRootfs(t *testing.T) {
	yaml := `services:
  writable:
    image: alpine
  readonly:
    image: alpine
    read_only: true
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

	rule := &Rule006WritableRootfs{}
	findings, err := rule.Evaluate(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].RuleID != "RULE-006" {
		t.Errorf("expected RULE-006, got %s", findings[0].RuleID)
	}
}
