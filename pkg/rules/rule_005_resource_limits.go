package rules

import (
	"fmt"
)

type Rule005ResourceLimits struct{}

func init() {
	Register(&Rule005ResourceLimits{})
}

func (r *Rule005ResourceLimits) ID() string {
	return "RULE-005"
}

func (r *Rule005ResourceLimits) Name() string {
	return "Missing Resource Limits"
}

func (r *Rule005ResourceLimits) Severity() Severity {
	return SeverityHigh
}

func (r *Rule005ResourceLimits) Description() string {
	return "Lack of CPU, memory, restart, or process limits makes the host vulnerable to Denial of Service (DoS) attacks."
}

func (r *Rule005ResourceLimits) Mitigation() string {
	return "Define 'cpus', 'memory', restart limits, and ulimits (nofile, nproc) in your container specification."
}

func (r *Rule005ResourceLimits) AttackVector() string {
	return "Without CPU and memory limits, an unconstrained or compromised container process can exhaust host memory and CPU, triggering the kernel OOM killer against host daemons or starving co-located containers."
}

func (r *Rule005ResourceLimits) Targets() []TargetType {
	return []TargetType{TargetCompose}
}

func (r *Rule005ResourceLimits) Evaluate(ctx *ScanContext) ([]Finding, error) {
	if ctx.Compose == nil {
		return nil, nil
	}

	var findings []Finding

	for _, svc := range ctx.Compose.Services {
		hasCPU := svc.CPUs != ""
		hasMemory := svc.MemLimit != ""

		if svc.Deploy != nil && svc.Deploy.Resources != nil && svc.Deploy.Resources.Limits != nil {
			if svc.Deploy.Resources.Limits.CPUs != "" {
				hasCPU = true
			}
			if svc.Deploy.Resources.Limits.Memory != "" {
				hasMemory = true
			}
		}

		if !hasCPU || !hasMemory {
			var missing []string
			if !hasCPU {
				missing = append(missing, "CPU")
			}
			if !hasMemory {
				missing = append(missing, "memory")
			}

			findings = append(findings, Finding{
				RuleID:       r.ID(),
				RuleName:     r.Name(),
				Severity:     r.Severity(),
				TargetFile:   ctx.FilePath,
				Line:         svc.Line,
				Message:      fmt.Sprintf("Service %q is missing resource limits (%v)", svc.Name, missing),
				Mitigation:   r.Mitigation(),
				AttackVector: r.AttackVector(),
			})
		}
	}

	return findings, nil
}
