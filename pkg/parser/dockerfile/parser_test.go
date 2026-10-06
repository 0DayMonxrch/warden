package dockerfile

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseSimpleDockerfile(t *testing.T) {
	dockerfileContent := `FROM alpine:3.19
USER 1000
ENTRYPOINT ["/bin/sh"]
`
	parsed, err := ParseBytes([]byte(dockerfileContent))
	if err != nil {
		t.Fatalf("unexpected error parsing dockerfile: %v", err)
	}

	if len(parsed.Instructions) != 3 {
		t.Fatalf("expected 3 instructions, got %d", len(parsed.Instructions))
	}

	// 1. FROM
	from := parsed.Instructions[0]
	if from.Name != "FROM" {
		t.Errorf("expected instruction name 'FROM', got %q", from.Name)
	}
	if len(from.Args) != 1 || from.Args[0] != "alpine:3.19" {
		t.Errorf("expected args ['alpine:3.19'], got %v", from.Args)
	}
	if from.StartLine != 1 || from.EndLine != 1 {
		t.Errorf("expected lines 1-1, got %d-%d", from.StartLine, from.EndLine)
	}

	// 2. USER
	user := parsed.Instructions[1]
	if user.Name != "USER" {
		t.Errorf("expected instruction name 'USER', got %q", user.Name)
	}
	if len(user.Args) != 1 || user.Args[0] != "1000" {
		t.Errorf("expected args ['1000'], got %v", user.Args)
	}

	// 3. Stages
	if len(parsed.Stages) != 1 {
		t.Fatalf("expected 1 stage, got %d", len(parsed.Stages))
	}
	if parsed.Stages[0].BaseImage != "alpine:3.19" {
		t.Errorf("expected base image 'alpine:3.19', got %q", parsed.Stages[0].BaseImage)
	}
}

func TestParseMultiStageAndFlags(t *testing.T) {
	dockerfileContent := `# syntax=docker/dockerfile:1
ARG GO_VERSION=1.22
FROM golang:${GO_VERSION}-alpine AS builder
WORKDIR /src
RUN go build -o app .

FROM alpine:3.19
COPY --from=builder --chown=appuser:appuser /src/app /bin/app
USER appuser
CMD ["/bin/app"]
`
	parsed, err := ParseBytes([]byte(dockerfileContent))
	if err != nil {
		t.Fatalf("unexpected error parsing multi-stage dockerfile: %v", err)
	}

	if len(parsed.Stages) != 3 { // Stage 0 (global ARG), Stage 1 (builder), Stage 2 (final)
		t.Fatalf("expected 3 stages (including global), got %d", len(parsed.Stages))
	}

	builderStage := parsed.Stages[1]
	if builderStage.Name != "builder" {
		t.Errorf("expected stage name 'builder', got %q", builderStage.Name)
	}
	if builderStage.BaseImage != "golang:${GO_VERSION}-alpine" {
		t.Errorf("expected base image 'golang:${GO_VERSION}-alpine', got %q", builderStage.BaseImage)
	}

	// Verify COPY flags
	var copyInst *Instruction
	for _, inst := range parsed.Instructions {
		if inst.Name == "COPY" {
			copyInst = &inst
			break
		}
	}
	if copyInst == nil {
		t.Fatal("expected COPY instruction, none found")
	}

	if len(copyInst.Flags) != 2 {
		t.Fatalf("expected 2 flags on COPY, got %d (%v)", len(copyInst.Flags), copyInst.Flags)
	}

	hasFromFlag := false
	hasChownFlag := false
	for _, f := range copyInst.Flags {
		if f == "--from=builder" {
			hasFromFlag = true
		}
		if f == "--chown=appuser:appuser" {
			hasChownFlag = true
		}
	}
	if !hasFromFlag || !hasChownFlag {
		t.Errorf("missing expected flags on COPY: %v", copyInst.Flags)
	}
}

func TestParseMultilineInstruction(t *testing.T) {
	dockerfileContent := `FROM alpine:3.19
RUN apk update && \
    apk add --no-cache curl && \
    rm -rf /var/cache/apk/*
`
	parsed, err := ParseBytes([]byte(dockerfileContent))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	run := parsed.Instructions[1]
	if run.Name != "RUN" {
		t.Errorf("expected 'RUN', got %q", run.Name)
	}
	if run.StartLine != 2 || run.EndLine != 4 {
		t.Errorf("expected lines 2-4, got %d-%d", run.StartLine, run.EndLine)
	}
}

func TestJSONAndHumanOutput(t *testing.T) {
	dockerfileContent := `FROM alpine:3.19
USER 1000
`
	parsed, err := ParseBytes([]byte(dockerfileContent))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	jsonOut, err := parsed.ToJSON()
	if err != nil {
		t.Fatalf("failed to format JSON: %v", err)
	}

	var jsonMap map[string]interface{}
	if err := json.Unmarshal([]byte(jsonOut), &jsonMap); err != nil {
		t.Fatalf("produced invalid JSON: %v", err)
	}

	humanOut := parsed.ToHumanReadable()
	if !strings.Contains(humanOut, "Stage 0: FROM alpine:3.19") {
		t.Errorf("human output missing stage header: %s", humanOut)
	}
	if !strings.Contains(humanOut, "USER") {
		t.Errorf("human output missing USER instruction: %s", humanOut)
	}
}
