package rules

import (
	"testing"

	"github.com/0DayMonxrch/warden/pkg/parser/compose"
	"github.com/0DayMonxrch/warden/pkg/parser/dockerfile"
)

func TestRule002DockerfileRoot(t *testing.T) {
	// 1. Dockerfile missing USER
	dfNoUser := `FROM alpine:3.19
RUN echo "test"
`
	parsedNoUser, err := dockerfile.ParseBytes([]byte(dfNoUser))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx := &ScanContext{
		FilePath:   "Dockerfile",
		TargetType: TargetDockerfile,
		Dockerfile: parsedNoUser,
	}

	rule := &Rule002RunningAsRoot{}
	findings, err := rule.Evaluate(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for missing USER, got %d", len(findings))
	}

	// 2. Dockerfile explicit USER root
	dfUserRoot := `FROM alpine:3.19
USER root
`
	parsedRoot, _ := dockerfile.ParseBytes([]byte(dfUserRoot))
	ctx.Dockerfile = parsedRoot
	findings, _ = rule.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for USER root, got %d", len(findings))
	}

	// 3. Dockerfile with non-root user
	dfNonRoot := `FROM alpine:3.19
USER 10001
`
	parsedNonRoot, _ := dockerfile.ParseBytes([]byte(dfNonRoot))
	ctx.Dockerfile = parsedNonRoot
	findings, _ = rule.Evaluate(ctx)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for non-root USER, got %d", len(findings))
	}
}

func TestRule002ComposeRoot(t *testing.T) {
	yaml := `services:
  web:
    image: nginx
  db:
    image: postgres
    user: "1000:1000"
  admin:
    image: alpine
    user: "0"
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

	rule := &Rule002RunningAsRoot{}
	findings, err := rule.Evaluate(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// web has no user (1 finding), admin has user 0 (1 finding), db has user 1000 (0 findings)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
}
