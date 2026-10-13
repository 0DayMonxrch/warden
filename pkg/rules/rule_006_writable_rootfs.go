package rules

import (
	"fmt"
)

type Rule006WritableRootfs struct{}

func init() {
	Register(&Rule006WritableRootfs{})
}

func (r *Rule006WritableRootfs) ID() string {
	return "RULE-006"
}

func (r *Rule006WritableRootfs) Name() string {
	return "Writable Root Filesystem"
}

func (r *Rule006WritableRootfs) Severity() Severity {
	return SeverityMedium
}

func (r *Rule006WritableRootfs) Description() string {
	return "A writable root filesystem enables attackers to modify application files or write malicious binaries."
}

func (r *Rule006WritableRootfs) Mitigation() string {
	return "Set 'read_only: true' and use tmpfs mounts for temporary directory writes."
}

func (r *Rule006WritableRootfs) AttackVector() string {
	return "A writable root filesystem allows an attacker who achieves arbitrary code execution to persist malicious scripts, overwrite trusted libraries, or drop backdoor binaries within the container."
}

func (r *Rule006WritableRootfs) Targets() []TargetType {
	return []TargetType{TargetCompose}
}

func (r *Rule006WritableRootfs) Evaluate(ctx *ScanContext) ([]Finding, error) {
	if ctx.Compose == nil {
		return nil, nil
	}

	var findings []Finding

	for _, svc := range ctx.Compose.Services {
		if svc.ReadOnly == nil || !*svc.ReadOnly {
			line := svc.ReadOnlyLine
			if line == 0 {
				line = svc.Line
			}
			findings = append(findings, Finding{
				RuleID:       r.ID(),
				RuleName:     r.Name(),
				Severity:     r.Severity(),
				TargetFile:   ctx.FilePath,
				Line:         line,
				Message:      fmt.Sprintf("Service %q does not configure a read-only root filesystem ('read_only: true')", svc.Name),
				Mitigation:   r.Mitigation(),
				AttackVector: r.AttackVector(),
			})
		}
	}

	return findings, nil
}
