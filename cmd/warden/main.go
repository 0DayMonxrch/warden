package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/0DayMonxrch/warden/pkg/parser/compose"
	"github.com/0DayMonxrch/warden/pkg/parser/dockerfile"
	"github.com/0DayMonxrch/warden/pkg/report"
	"github.com/0DayMonxrch/warden/pkg/rules"
	"github.com/spf13/cobra"
)

var (
	parseType      string
	parseFormat    string
	parseOutputDir string

	scanType      string
	scanFormat    string
	scanThreshold string
	scanOutputDir string
	scanCIMode    bool
)

func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "warden",
		Short: "Warden is a static security scanner for Dockerfiles and Kubernetes manifests",
		Long: `Warden performs static security analysis on container definitions and orchestrator
manifests to detect container-escape and privilege-escalation risks before deployment.`,
	}

	rootCmd.AddCommand(newParseCmd())
	rootCmd.AddCommand(newScanCmd())
	return rootCmd
}

func newParseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "parse [file]",
		Short: "Parse a Dockerfile or Docker Compose file into an AST",
		Long: `Parse transforms input Dockerfiles or Compose files into a structured
Abstract Syntax Tree (AST), outputting either human-readable formatted text or JSON,
and storing the AST under results/parsed-output.json.`,
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		RunE:         runParse,
	}

	cmd.Flags().StringVarP(&parseType, "type", "t", "auto", "Target artifact type ('auto', 'dockerfile', 'compose')")
	cmd.Flags().StringVarP(&parseFormat, "format", "f", "text", "Output format ('text' or 'json')")
	cmd.Flags().StringVarP(&parseOutputDir, "output-dir", "o", "results", "Directory to persist parsed AST output")

	return cmd
}

func newScanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan [file]",
		Short: "Scan a Dockerfile or Docker Compose file for security misconfigurations",
		Long: `Scan performs full static analysis against the target configuration using
Warden's compiled-in rule registry, persists results in results/, and gates CI pipelines.`,
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		RunE:         runScan,
	}

	cmd.Flags().StringVarP(&scanType, "type", "t", "auto", "Target artifact type ('auto', 'dockerfile', 'compose')")
	cmd.Flags().StringVarP(&scanFormat, "format", "f", "text", "Console output format ('text' or 'json')")
	cmd.Flags().StringVarP(&scanThreshold, "severity-threshold", "s", "HIGH", "CI failure threshold ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')")
	cmd.Flags().StringVarP(&scanOutputDir, "output-dir", "o", "results", "Directory to persist scan results")
	cmd.Flags().BoolVar(&scanCIMode, "ci", false, "Enable CI mode: exit with code 1 if findings meet or exceed severity threshold")

	return cmd
}

func detectTargetType(filePath string, data []byte, requestedType string) (rules.TargetType, error) {
	req := strings.ToLower(strings.TrimSpace(requestedType))
	switch req {
	case "dockerfile":
		return rules.TargetDockerfile, nil
	case "compose", "docker-compose":
		return rules.TargetCompose, nil
	case "auto", "":
		// Detect from file path
		base := strings.ToLower(filepath.Base(filePath))
		if strings.Contains(base, "dockerfile") {
			return rules.TargetDockerfile, nil
		}
		if strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml") || strings.Contains(base, "compose") {
			return rules.TargetCompose, nil
		}

		// Sniff data content
		content := string(data)
		if strings.HasPrefix(strings.TrimSpace(content), "FROM ") || strings.Contains(content, "\nFROM ") {
			return rules.TargetDockerfile, nil
		}
		if strings.Contains(content, "services:") || strings.Contains(content, "version:") {
			return rules.TargetCompose, nil
		}

		return "", fmt.Errorf("unable to detect target type for %q; please specify --type=dockerfile or --type=compose", filePath)
	default:
		return "", fmt.Errorf("unsupported type %q: choose 'dockerfile', 'compose', or 'auto'", requestedType)
	}
}

func readInput(args []string) (string, []byte, error) {
	if len(args) == 0 || args[0] == "-" {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) != 0 {
			return "", nil, fmt.Errorf("no file specified and no data piped via stdin. Usage: warden scan <path>")
		}
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", nil, fmt.Errorf("failed to read from stdin: %w", err)
		}
		return "<stdin>", data, nil
	}

	filePath := args[0]
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}
	return filePath, data, nil
}

func runParse(cmd *cobra.Command, args []string) error {
	filePath, data, err := readInput(args)
	if err != nil {
		return err
	}

	targetType, err := detectTargetType(filePath, data, parseType)
	if err != nil {
		return err
	}

	format := strings.ToLower(strings.TrimSpace(parseFormat))
	if format != "text" && format != "json" {
		return fmt.Errorf("unsupported format %q: choose 'text' or 'json'", parseFormat)
	}

	var parsedJSON string
	var humanText string

	if targetType == rules.TargetDockerfile {
		parsed, parseErr := dockerfile.ParseBytes(data)
		if parseErr != nil {
			return fmt.Errorf("dockerfile parse error: %w", parseErr)
		}
		parsed.FilePath = filePath
		parsedJSON, _ = parsed.ToJSON()
		humanText = parsed.ToHumanReadable()
	} else {
		parsed, parseErr := compose.ParseBytes(data)
		if parseErr != nil {
			return fmt.Errorf("compose parse error: %w", parseErr)
		}
		parsed.FilePath = filePath
		parsedJSON, _ = parsed.ToJSON()
		humanText = parsed.ToHumanReadable()
	}

	// Persist to results/parsed-output.json
	if parseOutputDir != "" {
		if err := os.MkdirAll(parseOutputDir, 0755); err == nil {
			_ = os.WriteFile(filepath.Join(parseOutputDir, "parsed-output.json"), []byte(parsedJSON), 0644)
		}
	}

	if format == "json" {
		fmt.Println(parsedJSON)
	} else {
		fmt.Print(humanText)
	}

	return nil
}

func runScan(cmd *cobra.Command, args []string) error {
	filePath, data, err := readInput(args)
	if err != nil {
		return err
	}

	targetType, err := detectTargetType(filePath, data, scanType)
	if err != nil {
		return err
	}

	format := strings.ToLower(strings.TrimSpace(scanFormat))
	if format != "text" && format != "json" {
		return fmt.Errorf("unsupported format %q: choose 'text' or 'json'", scanFormat)
	}

	threshold := rules.Severity(strings.ToUpper(strings.TrimSpace(scanThreshold)))
	if threshold.Level() == 0 {
		return fmt.Errorf("invalid severity threshold %q: choose 'CRITICAL', 'HIGH', 'MEDIUM', or 'LOW'", scanThreshold)
	}

	scanCtx := &rules.ScanContext{
		FilePath:   filePath,
		TargetType: targetType,
	}

	var parsedJSON string

	// Step 1: Parse and validate syntax
	if targetType == rules.TargetDockerfile {
		parsed, parseErr := dockerfile.ParseBytes(data)
		if parseErr != nil {
			return fmt.Errorf("dockerfile syntax error: %w", parseErr)
		}
		parsed.FilePath = filePath
		scanCtx.Dockerfile = parsed
		parsedJSON, _ = parsed.ToJSON()
	} else {
		parsed, parseErr := compose.ParseBytes(data)
		if parseErr != nil {
			return fmt.Errorf("compose syntax error: %w", parseErr)
		}
		parsed.FilePath = filePath
		scanCtx.Compose = parsed
		parsedJSON, _ = parsed.ToJSON()
	}

	// Step 2: Store parsed output in results/parsed-output.json
	if scanOutputDir != "" {
		if err := os.MkdirAll(scanOutputDir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory %s: %w", scanOutputDir, err)
		}
		parsedPath := filepath.Join(scanOutputDir, "parsed-output.json")
		if err := os.WriteFile(parsedPath, []byte(parsedJSON), 0644); err != nil {
			return fmt.Errorf("failed to save parsed AST to %s: %w", parsedPath, err)
		}
	}

	// Step 3: Run Rule Engine
	findings, scanErr := rules.Scan(scanCtx)
	if scanErr != nil {
		return fmt.Errorf("scan error: %w", scanErr)
	}

	// Step 4: Generate Report and Persist in results/
	rep := report.NewReport(filePath, targetType, findings)
	if scanOutputDir != "" {
		if err := rep.Save(scanOutputDir); err != nil {
			return fmt.Errorf("failed to save scan reports: %w", err)
		}
	}

	// Step 5: Render Console Output
	if format == "json" {
		out, jsonErr := rep.ToJSON()
		if jsonErr != nil {
			return jsonErr
		}
		fmt.Println(out)
	} else {
		fmt.Print(rep.ToHumanReadable())
	}

	// Step 6: CI Mode Gating
	if scanCIMode {
		hasViolation := false
		for _, f := range findings {
			if f.Severity.MeetsThreshold(threshold) {
				hasViolation = true
				break
			}
		}

		if hasViolation {
			return fmt.Errorf("CI gate failed: findings at or above %s severity detected", threshold)
		}
	}

	return nil
}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}
