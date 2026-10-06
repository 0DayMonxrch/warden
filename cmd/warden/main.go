package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/0DayMonxrch/warden/pkg/parser/dockerfile"
	"github.com/spf13/cobra"
)

var (
	parseType   string
	parseFormat string
)

func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "warden",
		Short: "Warden is a static security scanner for Dockerfiles and Kubernetes manifests",
		Long: `Warden performs static security analysis on container definitions and orchestrator
manifests to detect container-escape and privilege-escalation risks before deployment.`,
	}

	rootCmd.AddCommand(newParseCmd())
	return rootCmd
}

func newParseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "parse [file]",
		Short: "Parse a Dockerfile or Kubernetes manifest into an AST",
		Long: `Parse transforms input Dockerfiles or Kubernetes manifests into a structured
Abstract Syntax Tree (AST), outputting either human-readable formatted text or JSON.`,
		Args: cobra.MaximumNArgs(1),
		RunE: runParse,
	}

	cmd.Flags().StringVarP(&parseType, "type", "t", "dockerfile", "Target artifact type ('dockerfile')")
	cmd.Flags().StringVarP(&parseFormat, "format", "f", "text", "Output format ('text' or 'json')")

	return cmd
}

func runParse(cmd *cobra.Command, args []string) error {
	targetType := strings.ToLower(strings.TrimSpace(parseType))
	if targetType != "dockerfile" {
		return fmt.Errorf("unsupported parse type %q: currently supported types are: dockerfile", parseType)
	}

	format := strings.ToLower(strings.TrimSpace(parseFormat))
	if format != "text" && format != "json" {
		return fmt.Errorf("unsupported format %q: choose 'text' or 'json'", parseFormat)
	}

	var parsed *dockerfile.ParsedDockerfile
	var err error

	if len(args) == 0 || args[0] == "-" {
		// Read from stdin
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) != 0 {
			return fmt.Errorf("no file specified and no data piped via stdin. Usage: warden parse --type=dockerfile <path>")
		}
		data, readErr := io.ReadAll(os.Stdin)
		if readErr != nil {
			return fmt.Errorf("failed to read from stdin: %w", readErr)
		}
		parsed, err = dockerfile.ParseBytes(data)
	} else {
		filePath := args[0]
		parsed, err = dockerfile.ParseFile(filePath)
	}

	if err != nil {
		return fmt.Errorf("parse error: %w", err)
	}

	if format == "json" {
		out, jsonErr := parsed.ToJSON()
		if jsonErr != nil {
			return jsonErr
		}
		fmt.Println(out)
	} else {
		fmt.Print(parsed.ToHumanReadable())
	}

	return nil
}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}
