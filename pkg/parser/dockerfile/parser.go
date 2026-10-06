package dockerfile

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/moby/buildkit/frontend/dockerfile/parser"
)

// Parse reads Dockerfile content from an io.Reader, parses it using BuildKit,
// and constructs a structured ParsedDockerfile representation.
func Parse(r io.Reader) (*ParsedDockerfile, error) {
	result, err := parser.Parse(r)
	if err != nil {
		return nil, fmt.Errorf("failed to parse dockerfile: %w", err)
	}

	return fromBuildKitResult(result, "")
}

// ParseBytes parses Dockerfile content from raw bytes.
func ParseBytes(data []byte) (*ParsedDockerfile, error) {
	return Parse(bytes.NewReader(data))
}

// ParseFile reads and parses a Dockerfile from the specified filesystem path.
func ParseFile(path string) (*ParsedDockerfile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open dockerfile at %s: %w", path, err)
	}
	defer f.Close()

	result, err := parser.Parse(f)
	if err != nil {
		return nil, fmt.Errorf("failed to parse dockerfile at %s: %w", path, err)
	}

	return fromBuildKitResult(result, path)
}

// fromBuildKitResult maps the low-level BuildKit parse tree into Warden's ParsedDockerfile model.
func fromBuildKitResult(res *parser.Result, filePath string) (*ParsedDockerfile, error) {
	if res == nil || res.AST == nil {
		return nil, fmt.Errorf("empty or invalid parse result")
	}

	parsed := &ParsedDockerfile{
		FilePath:    filePath,
		EscapeToken: string(res.EscapeToken),
		RawResult:   res,
	}

	for _, w := range res.Warnings {
		loc := ""
		if w.Location != nil {
			loc = fmt.Sprintf(" (line %d)", w.Location.Start.Line)
		}
		parsed.Warnings = append(parsed.Warnings, fmt.Sprintf("%s%s", w.Short, loc))
	}

	var currentStage *Stage
	stageIndex := -1

	for _, node := range res.AST.Children {
		inst := convertNode(node, max(stageIndex, 0))

		// Check if this instruction starts a new build stage (FROM)
		if inst.Name == "FROM" {
			stageIndex++
			inst.Stage = stageIndex

			baseImage, stageName := parseFromArgs(inst.Args)
			newStage := Stage{
				Index:        stageIndex,
				BaseImage:    baseImage,
				Name:         stageName,
				Instructions: []Instruction{inst},
			}
			parsed.Stages = append(parsed.Stages, newStage)
			currentStage = &parsed.Stages[len(parsed.Stages)-1]
		} else {
			if currentStage == nil {
				// Instructions prior to the first FROM (e.g. global ARG)
				globalStage := Stage{
					Index:        0,
					BaseImage:    "",
					Name:         "global",
					Instructions: []Instruction{inst},
				}
				parsed.Stages = append(parsed.Stages, globalStage)
				currentStage = &parsed.Stages[0]
				stageIndex = 0
			} else {
				currentStage.Instructions = append(currentStage.Instructions, inst)
			}
		}

		parsed.Instructions = append(parsed.Instructions, inst)
	}

	return parsed, nil
}

// convertNode converts a BuildKit parser.Node into a Warden Instruction.
func convertNode(node *parser.Node, stageIndex int) Instruction {
	inst := Instruction{
		Name:      strings.ToUpper(node.Value),
		Flags:     node.Flags,
		StartLine: node.StartLine,
		EndLine:   node.EndLine,
		Original:  strings.TrimSpace(node.Original),
		Stage:     stageIndex,
		RawNode:   node,
	}

	// In BuildKit's AST:
	// node.Next points to the first argument token.
	// Subsequent tokens in the s-expression are chained via curr.Next.
	for curr := node.Next; curr != nil; curr = curr.Next {
		inst.Args = append(inst.Args, curr.Value)
	}

	return inst
}

// parseFromArgs extracts the base image and optional alias ("AS <name>") from FROM arguments.
func parseFromArgs(args []string) (string, string) {
	if len(args) == 0 {
		return "", ""
	}

	baseImage := args[0]
	var stageName string

	for i := 1; i < len(args); i++ {
		if strings.EqualFold(args[i], "as") && i+1 < len(args) {
			stageName = args[i+1]
			break
		}
	}

	return baseImage, stageName
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
