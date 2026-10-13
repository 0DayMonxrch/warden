package rules

import (
	"testing"

	"github.com/0DayMonxrch/warden/pkg/parser/compose"
)

func TestEngineScanCompose(t *testing.T) {
	yaml := `services:
  vulnerable:
    image: alpine
    privileged: true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
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

	findings, err := Scan(ctx)
	if err != nil {
		t.Fatalf("unexpected scan error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected findings, got 0")
	}

	// Verify findings are sorted by severity descending
	for i := 0; i < len(findings)-1; i++ {
		if findings[i].Severity.Level() < findings[i+1].Severity.Level() {
			t.Errorf("findings not sorted by severity: %s followed by %s", findings[i].Severity, findings[i+1].Severity)
		}
	}

	// Top finding should be CRITICAL (RULE-001)
	if findings[0].Severity != SeverityCritical || findings[0].RuleID != "RULE-001" {
		t.Errorf("expected top finding to be RULE-001 CRITICAL, got %s %s", findings[0].RuleID, findings[0].Severity)
	}
}
