package rules

import (
	"fmt"
	"strings"

	"github.com/0DayMonxrch/warden/pkg/parser/dockerfile"
)

type Rule002RunningAsRoot struct{}

func init() {
	Register(&Rule002RunningAsRoot{})
}

func (r *Rule002RunningAsRoot) ID() string {
	return "RULE-002"
}

func (r *Rule002RunningAsRoot) Name() string {
	return "Container Running as Root"
}

func (r *Rule002RunningAsRoot) Severity() Severity {
	return SeverityHigh
}

func (r *Rule002RunningAsRoot) Description() string {
	return "Running containers as root increases the impact of privilege escalation attacks."
}

func (r *Rule002RunningAsRoot) Mitigation() string {
	return "Define a non-root user in the Dockerfile using USER instruction or specify user in Docker Compose."
}

func (r *Rule002RunningAsRoot) AttackVector() string {
	return "Containers running as root (UID 0) possess elevated privileges inside the mount and user namespaces. Any kernel or container runtime escape directly inherits root privileges on the underlying host."
}

func (r *Rule002RunningAsRoot) Targets() []TargetType {
	return []TargetType{TargetDockerfile, TargetCompose}
}

func (r *Rule002RunningAsRoot) Evaluate(ctx *ScanContext) ([]Finding, error) {
	var findings []Finding

	if ctx.TargetType == TargetDockerfile && ctx.Dockerfile != nil {
		dockerFindings := r.evaluateDockerfile(ctx)
		findings = append(findings, dockerFindings...)
	}

	if ctx.TargetType == TargetCompose && ctx.Compose != nil {
		composeFindings := r.evaluateCompose(ctx)
		findings = append(findings, composeFindings...)
	}

	return findings, nil
}

func (r *Rule002RunningAsRoot) evaluateDockerfile(ctx *ScanContext) []Finding {
	var findings []Finding
	stages := ctx.Dockerfile.Stages
	if len(stages) == 0 {
		return findings
	}

	// We inspect the final production stage, as that represents the runtime image
	finalStage := stages[len(stages)-1]

	var lastUserInst *dockerfile.Instruction
	for i := range finalStage.Instructions {
		inst := &finalStage.Instructions[i]
		if inst.Name == "USER" {
			lastUserInst = inst
		}
	}

	if lastUserInst == nil {
		// No USER instruction in final stage
		fromLine := 1
		for _, inst := range finalStage.Instructions {
			if inst.Name == "FROM" {
				fromLine = inst.StartLine
				break
			}
		}

		stageDesc := finalStage.BaseImage
		if finalStage.Name != "" {
			stageDesc = fmt.Sprintf("%s AS %s", finalStage.BaseImage, finalStage.Name)
		}

		findings = append(findings, Finding{
			RuleID:       r.ID(),
			RuleName:     r.Name(),
			Severity:     r.Severity(),
			TargetFile:   ctx.FilePath,
			Line:         fromLine,
			Message:      fmt.Sprintf("Final build stage (%s) does not specify a non-root USER instruction; defaults to root (UID 0)", stageDesc),
			Mitigation:   r.Mitigation(),
			AttackVector: r.AttackVector(),
		})
	} else {
		// USER instruction present, check if root
		userVal := ""
		if len(lastUserInst.Args) > 0 {
			userVal = strings.TrimSpace(lastUserInst.Args[0])
		}

		if isRootUser(userVal) {
			findings = append(findings, Finding{
				RuleID:       r.ID(),
				RuleName:     r.Name(),
				Severity:     r.Severity(),
				TargetFile:   ctx.FilePath,
				Line:         lastUserInst.StartLine,
				EndLine:      lastUserInst.EndLine,
				Message:      fmt.Sprintf("Container execution context explicitly configured to run as root user %q", userVal),
				Mitigation:   r.Mitigation(),
				AttackVector: r.AttackVector(),
			})
		}
	}

	return findings
}

func (r *Rule002RunningAsRoot) evaluateCompose(ctx *ScanContext) []Finding {
	var findings []Finding

	for _, svc := range ctx.Compose.Services {
		if !svc.HasUser {
			findings = append(findings, Finding{
				RuleID:       r.ID(),
				RuleName:     r.Name(),
				Severity:     r.Severity(),
				TargetFile:   ctx.FilePath,
				Line:         svc.Line,
				Message:      fmt.Sprintf("Service %q does not specify a 'user' directive and runs as root by default", svc.Name),
				Mitigation:   r.Mitigation(),
				AttackVector: r.AttackVector(),
			})
		} else if isRootUser(svc.User) {
			line := svc.UserLine
			if line == 0 {
				line = svc.Line
			}
			findings = append(findings, Finding{
				RuleID:       r.ID(),
				RuleName:     r.Name(),
				Severity:     r.Severity(),
				TargetFile:   ctx.FilePath,
				Line:         line,
				Message:      fmt.Sprintf("Service %q is explicitly configured to run as root user %q", svc.Name, svc.User),
				Mitigation:   r.Mitigation(),
				AttackVector: r.AttackVector(),
			})
		}
	}

	return findings
}

func isRootUser(user string) bool {
	u := strings.TrimSpace(strings.ToLower(user))
	return u == "" || u == "root" || u == "0" || u == "0:0" || strings.HasPrefix(u, "0:") || strings.HasPrefix(u, "root:")
}
