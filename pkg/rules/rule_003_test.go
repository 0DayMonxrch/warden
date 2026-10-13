package rules

import (
	"testing"

	"github.com/0DayMonxrch/warden/pkg/parser/compose"
)

func TestRule003LinuxCapabilities(t *testing.T) {
	yaml := `services:
  priv:
    image: alpine
    privileged: true
  nodrop:
    image: alpine
    cap_add:
      - NET_ADMIN
  secure:
    image: alpine
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
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

	rule := &Rule003LinuxCapabilities{}
	findings, err := rule.Evaluate(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// priv triggers privileged, nodrop triggers missing cap_drop ALL, secure triggers nothing
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
}
