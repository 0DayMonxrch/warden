package rules

import (
	"fmt"
	"strings"
)

type Rule003LinuxCapabilities struct{}

func init() {
	Register(&Rule003LinuxCapabilities{})
}

func (r *Rule003LinuxCapabilities) ID() string {
	return "RULE-003"
}

func (r *Rule003LinuxCapabilities) Name() string {
	return "Unnecessary Linux Capabilities"
}

func (r *Rule003LinuxCapabilities) Severity() Severity {
	return SeverityMedium
}

func (r *Rule003LinuxCapabilities) Description() string {
	return "Excessive Linux capabilities broaden the attack surface. Using --privileged grants all host capabilities."
}

func (r *Rule003LinuxCapabilities) Mitigation() string {
	return "Drop unneeded capabilities with 'cap_drop: [ALL]' and selectively add required ones with 'cap_add'. Never use privileged mode."
}

func (r *Rule003LinuxCapabilities) AttackVector() string {
	return "Excessive capabilities (e.g. CAP_SYS_ADMIN, CAP_NET_RAW) or privileged mode provide direct access to kernel interfaces, device nodes, and raw sockets, bypassing container isolation and facilitating escape."
}

func (r *Rule003LinuxCapabilities) Targets() []TargetType {
	return []TargetType{TargetCompose}
}

func (r *Rule003LinuxCapabilities) Evaluate(ctx *ScanContext) ([]Finding, error) {
	if ctx.Compose == nil {
		return nil, nil
	}

	var findings []Finding

	for _, svc := range ctx.Compose.Services {
		if svc.Privileged {
			line := svc.PrivilegedLine
			if line == 0 {
				line = svc.Line
			}
			findings = append(findings, Finding{
				RuleID:       r.ID(),
				RuleName:     r.Name(),
				Severity:     r.Severity(),
				TargetFile:   ctx.FilePath,
				Line:         line,
				Message:      fmt.Sprintf("Service %q enables privileged mode ('privileged: true'), granting all host capabilities and disabling container boundaries", svc.Name),
				Mitigation:   r.Mitigation(),
				AttackVector: r.AttackVector(),
			})
			continue
		}

		// Check if ALL capabilities are dropped
		hasDropAll := false
		for _, cap := range svc.CapDrop {
			if strings.EqualFold(strings.TrimSpace(cap), "all") {
				hasDropAll = true
				break
			}
		}

		if !hasDropAll {
			line := svc.CapDropLine
			if line == 0 {
				line = svc.Line
			}
			findings = append(findings, Finding{
				RuleID:       r.ID(),
				RuleName:     r.Name(),
				Severity:     r.Severity(),
				TargetFile:   ctx.FilePath,
				Line:         line,
				Message:      fmt.Sprintf("Service %q does not drop all default Linux capabilities ('cap_drop: [ALL]')", svc.Name),
				Mitigation:   r.Mitigation(),
				AttackVector: r.AttackVector(),
			})
		}
	}

	return findings, nil
}
