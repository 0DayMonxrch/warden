package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0DayMonxrch/warden/pkg/rules"
)

func TestReportFormattingAndSave(t *testing.T) {
	tmpDir := t.TempDir()

	findings := []rules.Finding{
		{
			RuleID:       "RULE-001",
			RuleName:     "Exposed Docker Daemon Socket",
			Severity:     rules.SeverityCritical,
			TargetFile:   "docker-compose.yml",
			Line:         10,
			Message:      "Service mounts docker daemon socket",
			Mitigation:   "Do not mount docker socket",
			AttackVector: "Host takeover",
		},
	}

	rep := NewReport("docker-compose.yml", rules.TargetCompose, findings)

	if rep.Summary.Total != 1 || rep.Summary.Critical != 1 {
		t.Fatalf("unexpected summary: %+v", rep.Summary)
	}

	// Verify JSON serialization
	jsonStr, err := rep.ToJSON()
	if err != nil {
		t.Fatalf("failed to format JSON: %v", err)
	}
	if !strings.Contains(jsonStr, "RULE-001") {
		t.Errorf("json missing RULE-001")
	}

	// Verify Human-readable serialization
	humanStr := rep.ToHumanReadable()
	if !strings.Contains(humanStr, "WARDEN SECURITY SCAN REPORT") {
		t.Errorf("missing title in human report")
	}
	if !strings.Contains(humanStr, "[CRITICAL]") {
		t.Errorf("missing severity tag in human report")
	}

	// Test Save
	if err := rep.Save(tmpDir); err != nil {
		t.Fatalf("failed to save report: %v", err)
	}

	if _, err := os.Stat(filepath.Join(tmpDir, "scan-output.json")); err != nil {
		t.Errorf("scan-output.json not found: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmpDir, "scan-output.txt")); err != nil {
		t.Errorf("scan-output.txt not found: %v", err)
	}
}
