package rules

import (
	"fmt"
	"strings"
)

type Rule004PrivilegeEscalation struct{}

func init() {
	Register(&Rule004PrivilegeEscalation{})
}

func (r *Rule004PrivilegeEscalation) ID() string {
	return "RULE-004"
}

func (r *Rule004PrivilegeEscalation) Name() string {
	return "In-Container Privilege Escalation Allowed"
}

func (r *Rule004PrivilegeEscalation) Severity() Severity {
	return SeverityMedium
}

func (r *Rule004PrivilegeEscalation) Description() string {
	return "Processes inside the container can gain new privileges via setuid or setgid binaries."
}

func (r *Rule004PrivilegeEscalation) Mitigation() string {
	return "Set security option 'no-new-privileges:true' in your container runtime or Compose configuration."
}

func (r *Rule004PrivilegeEscalation) AttackVector() string {
	return "Without the PR_SET_NO_NEW_PRIVS bit set ('no-new-privileges:true'), attackers with non-root access inside the container can leverage local SUID/SGID binaries to escalate privileges to root."
}

func (r *Rule004PrivilegeEscalation) Targets() []TargetType {
	return []TargetType{TargetCompose}
}

func (r *Rule004PrivilegeEscalation) Evaluate(ctx *ScanContext) ([]Finding, error) {
	if ctx.Compose == nil {
		return nil, nil
	}

	var findings []Finding

	for _, svc := range ctx.Compose.Services {
		hasNoNewPrivs := false
		for _, opt := range svc.SecurityOpt {
			cleaned := strings.ToLower(strings.TrimSpace(opt))
			if cleaned == "no-new-privileges:true" || cleaned == "no-new-privileges" {
				hasNoNewPrivs = true
				break
			}
		}

		if !hasNoNewPrivs {
			line := svc.SecurityOptLine
			if line == 0 {
				line = svc.Line
			}
			findings = append(findings, Finding{
				RuleID:       r.ID(),
				RuleName:     r.Name(),
				Severity:     r.Severity(),
				TargetFile:   ctx.FilePath,
				Line:         line,
				Message:      fmt.Sprintf("Service %q does not set 'security_opt: [no-new-privileges:true]'", svc.Name),
				Mitigation:   r.Mitigation(),
				AttackVector: r.AttackVector(),
			})
		}
	}

	return findings, nil
}
