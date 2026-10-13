package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/0DayMonxrch/warden/pkg/rules"
)

// Summary provides aggregate counts of findings by severity.
type Summary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// Report represents the complete security analysis report.
type Report struct {
	TargetFile string          `json:"targetFile"`
	TargetType string          `json:"targetType"`
	ScannedAt  string          `json:"scannedAt"`
	Summary    Summary         `json:"summary"`
	Findings   []rules.Finding `json:"findings"`
}

// NewReport constructs a Report from findings and computes summary totals.
func NewReport(targetFile string, targetType rules.TargetType, findings []rules.Finding) *Report {
	rep := &Report{
		TargetFile: targetFile,
		TargetType: string(targetType),
		ScannedAt:  time.Now().UTC().Format(time.RFC3339),
		Findings:   findings,
	}

	rep.Summary.Total = len(findings)
	for _, f := range findings {
		switch f.Severity {
		case rules.SeverityCritical:
			rep.Summary.Critical++
		case rules.SeverityHigh:
			rep.Summary.High++
		case rules.SeverityMedium:
			rep.Summary.Medium++
		case rules.SeverityLow:
			rep.Summary.Low++
		}
	}

	return rep
}

// ToJSON formats the report as indented JSON.
func (r *Report) ToJSON() (string, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal report to JSON: %w", err)
	}
	return string(data), nil
}

// ToHumanReadable formats the report into a structured, readable text output.
func (r *Report) ToHumanReadable() string {
	var sb strings.Builder

	sb.WriteString("================================================================================\n")
	sb.WriteString("                          WARDEN SECURITY SCAN REPORT                           \n")
	sb.WriteString("================================================================================\n")
	sb.WriteString(fmt.Sprintf("Target File : %s\n", r.TargetFile))
	sb.WriteString(fmt.Sprintf("Target Type : %s\n", r.TargetType))
	sb.WriteString(fmt.Sprintf("Scanned At  : %s\n", r.ScannedAt))
	sb.WriteString("--------------------------------------------------------------------------------\n")
	sb.WriteString(fmt.Sprintf("Summary: %d findings [CRITICAL: %d, HIGH: %d, MEDIUM: %d, LOW: %d]\n",
		r.Summary.Total, r.Summary.Critical, r.Summary.High, r.Summary.Medium, r.Summary.Low))
	sb.WriteString("================================================================================\n\n")

	if len(r.Findings) == 0 {
		sb.WriteString("✔ No misconfigurations detected. Target configuration meets all security rules.\n")
		return sb.String()
	}

	for i, f := range r.Findings {
		lineInfo := "N/A"
		if f.Line > 0 {
			lineInfo = fmt.Sprintf("Line %d", f.Line)
			if f.EndLine > f.Line {
				lineInfo = fmt.Sprintf("Lines %d-%d", f.Line, f.EndLine)
			}
		}

		sb.WriteString(fmt.Sprintf("[%d] [%-8s] %s: %s\n", i+1, f.Severity, f.RuleID, f.RuleName))
		sb.WriteString(fmt.Sprintf("    Location     : %s (%s)\n", f.TargetFile, lineInfo))
		sb.WriteString(fmt.Sprintf("    Finding      : %s\n", f.Message))
		if f.AttackVector != "" {
			sb.WriteString(fmt.Sprintf("    Attack Vector: %s\n", f.AttackVector))
		}
		sb.WriteString(fmt.Sprintf("    Mitigation   : %s\n", f.Mitigation))
		sb.WriteString("--------------------------------------------------------------------------------\n")
	}

	return sb.String()
}

// SaveWrites stores the machine-readable JSON and human-readable text reports to the specified directory.
func (r *Report) Save(outputDir string) error {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create results directory %s: %w", outputDir, err)
	}

	jsonContent, err := r.ToJSON()
	if err != nil {
		return err
	}

	jsonPath := filepath.Join(outputDir, "scan-output.json")
	if err := os.WriteFile(jsonPath, []byte(jsonContent), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", jsonPath, err)
	}

	txtContent := r.ToHumanReadable()
	txtPath := filepath.Join(outputDir, "scan-output.txt")
	if err := os.WriteFile(txtPath, []byte(txtContent), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", txtPath, err)
	}

	return nil
}
