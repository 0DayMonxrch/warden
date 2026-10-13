package rules

import (
	"fmt"
	"strings"
)

type Rule001DockerSock struct{}

func init() {
	Register(&Rule001DockerSock{})
}

func (r *Rule001DockerSock) ID() string {
	return "RULE-001"
}

func (r *Rule001DockerSock) Name() string {
	return "Exposed Docker Daemon Socket"
}

func (r *Rule001DockerSock) Severity() Severity {
	return SeverityCritical
}

func (r *Rule001DockerSock) Description() string {
	return "Exposing /var/run/docker.sock allows containers full root access to the host Docker daemon, leading to potential host takeover."
}

func (r *Rule001DockerSock) Mitigation() string {
	return "Avoid mounting docker.sock. Use a scoped API proxy or eBPF/kernel-based drivers (e.g., Falco) for monitoring."
}

func (r *Rule001DockerSock) AttackVector() string {
	return "Mounting the Docker UNIX socket allows any process inside the container to issue API commands to the host Docker daemon, spin up privileged sibling containers mounting host root (/), and compromise the host."
}

func (r *Rule001DockerSock) Targets() []TargetType {
	return []TargetType{TargetCompose}
}

func (r *Rule001DockerSock) Evaluate(ctx *ScanContext) ([]Finding, error) {
	if ctx.Compose == nil {
		return nil, nil
	}

	var findings []Finding
	for _, svc := range ctx.Compose.Services {
		for _, vol := range svc.Volumes {
			if strings.Contains(vol.Source, "docker.sock") || strings.Contains(vol.Target, "docker.sock") {
				line := vol.Line
				if line == 0 {
					line = svc.Line
				}
				findings = append(findings, Finding{
					RuleID:       r.ID(),
					RuleName:     r.Name(),
					Severity:     r.Severity(),
					TargetFile:   ctx.FilePath,
					Line:         line,
					Message:      fmt.Sprintf("Service %q mounts Docker daemon socket: %s", svc.Name, vol.Raw),
					Mitigation:   r.Mitigation(),
					AttackVector: r.AttackVector(),
				})
			}
		}
	}

	return findings, nil
}
