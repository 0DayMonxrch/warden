package rules

import (
	"testing"

	"github.com/0DayMonxrch/warden/pkg/parser/compose"
)

func TestRule004PrivilegeEscalation(t *testing.T) {
	yaml := `services:
  insecure:
    image: alpine
  secure:
    image: alpine
    security_opt:
      - no-new-privileges:true
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

	rule := &Rule004PrivilegeEscalation{}
	findings, err := rule.Evaluate(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].RuleID != "RULE-004" {
		t.Errorf("expected RULE-004, got %s", findings[0].RuleID)
	}
}
