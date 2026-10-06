package dockerfile

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/moby/buildkit/frontend/dockerfile/parser"
)

// Instruction represents a single Dockerfile instruction (e.g., FROM, RUN, USER, COPY).
type Instruction struct {
	Name      string   `json:"name"`                // e.g. "FROM", "RUN", "USER"
	Args      []string `json:"args"`                // e.g. ["alpine:3.19", "as", "builder"] or ["appuser"]
	Flags     []string `json:"flags,omitempty"`     // e.g. ["--chown=1000:1000", "--from=builder"]
	StartLine int      `json:"startLine"`           // 1-indexed starting line
	EndLine   int      `json:"endLine"`             // 1-indexed ending line
	Original  string   `json:"original"`            // Raw line from source
	Stage     int      `json:"stage"`               // 0-indexed stage index this instruction belongs to

	// RawNode preserves the underlying BuildKit AST node for advanced queries.
	RawNode *parser.Node `json:"-"`
}

// Stage represents a build stage in a multi-stage Dockerfile starting with a FROM instruction.
type Stage struct {
	Index        int           `json:"index"`                  // 0-indexed stage order
	BaseImage    string        `json:"baseImage"`              // e.g. "golang:1.22-alpine"
	Name         string        `json:"name,omitempty"`         // AS <name>, e.g. "builder"
	Instructions []Instruction `json:"instructions"`           // Instructions within this stage
}

// ParsedDockerfile is the structured representation of a parsed Dockerfile.
type ParsedDockerfile struct {
	FilePath     string        `json:"filePath,omitempty"`
	EscapeToken  string        `json:"escapeToken"`
	Instructions []Instruction `json:"instructions"`
	Stages       []Stage       `json:"stages"`
	Warnings     []string      `json:"warnings,omitempty"`

	// RawResult preserves the full BuildKit result.
	RawResult *parser.Result `json:"-"`
}

// ToJSON formats the parsed Dockerfile as indented JSON.
func (p *ParsedDockerfile) ToJSON() (string, error) {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal dockerfile AST to JSON: %w", err)
	}
	return string(data), nil
}

// ToHumanReadable formats the parsed Dockerfile into an easy-to-read outline.
func (p *ParsedDockerfile) ToHumanReadable() string {
	var sb strings.Builder

	if p.FilePath != "" {
		sb.WriteString(fmt.Sprintf("File: %s\n", p.FilePath))
	}
	sb.WriteString(fmt.Sprintf("Escape Token: %q\n", p.EscapeToken))
	sb.WriteString(fmt.Sprintf("Total Instructions: %d | Total Stages: %d\n", len(p.Instructions), len(p.Stages)))

	if len(p.Warnings) > 0 {
		sb.WriteString("\nWarnings:\n")
		for _, w := range p.Warnings {
			sb.WriteString(fmt.Sprintf("  - %s\n", w))
		}
	}

	sb.WriteString("\nStages:\n")
	for _, stage := range p.Stages {
		stageHeader := fmt.Sprintf("  Stage %d: FROM %s", stage.Index, stage.BaseImage)
		if stage.Name != "" {
			stageHeader += fmt.Sprintf(" AS %s", stage.Name)
		}
		sb.WriteString(stageHeader + "\n")
		for _, inst := range stage.Instructions {
			lineInfo := fmt.Sprintf("L%d", inst.StartLine)
			if inst.StartLine != inst.EndLine {
				lineInfo = fmt.Sprintf("L%d-%d", inst.StartLine, inst.EndLine)
			}
			var flagStr string
			if len(inst.Flags) > 0 {
				flagStr = fmt.Sprintf(" [%s]", strings.Join(inst.Flags, " "))
			}
			argsStr := strings.Join(inst.Args, " ")
			sb.WriteString(fmt.Sprintf("    %-8s %-7s%s %s\n", lineInfo, inst.Name, flagStr, argsStr))
		}
	}

	return sb.String()
}
