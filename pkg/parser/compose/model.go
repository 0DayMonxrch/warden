package compose

import (
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// VolumeMount represents a mounted volume or bind mount in a service.
type VolumeMount struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"readOnly,omitempty"`
	Raw      string `json:"raw"`
	Line     int    `json:"line"`
}

// ResourceLimits represents CPU, memory, and process limits in deploy.resources.limits.
type ResourceLimits struct {
	CPUs   string `json:"cpus,omitempty"`
	Memory string `json:"memory,omitempty"`
	Pids   int64  `json:"pids,omitempty"`
	Line   int    `json:"line,omitempty"`
}

// ResourceConfig holds resource reservations and limits under deploy.resources.
type ResourceConfig struct {
	Limits *ResourceLimits `json:"limits,omitempty"`
}

// DeployConfig represents the deploy key in a Compose service.
type DeployConfig struct {
	Resources *ResourceConfig `json:"resources,omitempty"`
}

// ServiceConfig represents a parsed service specification in a Docker Compose file.
type ServiceConfig struct {
	Name            string        `json:"name"`
	Line            int           `json:"line"`
	Image           string        `json:"image,omitempty"`
	User            string        `json:"user,omitempty"`
	UserLine        int           `json:"userLine,omitempty"`
	HasUser         bool          `json:"hasUser"`
	Privileged      bool          `json:"privileged,omitempty"`
	PrivilegedLine  int           `json:"privilegedLine,omitempty"`
	CapAdd          []string      `json:"capAdd,omitempty"`
	CapAddLine      int           `json:"capAddLine,omitempty"`
	CapDrop         []string      `json:"capDrop,omitempty"`
	CapDropLine     int           `json:"capDropLine,omitempty"`
	SecurityOpt     []string      `json:"securityOpt,omitempty"`
	SecurityOptLine int           `json:"securityOptLine,omitempty"`
	ReadOnly        *bool         `json:"readOnly,omitempty"`
	ReadOnlyLine    int           `json:"readOnlyLine,omitempty"`
	Volumes         []VolumeMount `json:"volumes,omitempty"`
	Deploy          *DeployConfig `json:"deploy,omitempty"`
	MemLimit        string        `json:"memLimit,omitempty"`
	CPUs            string        `json:"cpus,omitempty"`

	// RawNode preserves the underlying YAML AST node for this service.
	RawNode *yaml.Node `json:"-"`
}

// ParsedCompose is the structured representation of a parsed docker-compose file.
type ParsedCompose struct {
	FilePath string          `json:"filePath,omitempty"`
	Version  string          `json:"version,omitempty"`
	Services []ServiceConfig `json:"services"`
	Warnings []string        `json:"warnings,omitempty"`

	// RawNode preserves the root YAML document AST.
	RawNode *yaml.Node `json:"-"`
}

// ToJSON formats the parsed Compose file as indented JSON.
func (c *ParsedCompose) ToJSON() (string, error) {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal compose AST to JSON: %w", err)
	}
	return string(data), nil
}

// ToHumanReadable formats the parsed Compose file into an easy-to-read summary.
func (c *ParsedCompose) ToHumanReadable() string {
	var sb strings.Builder

	if c.FilePath != "" {
		sb.WriteString(fmt.Sprintf("File: %s\n", c.FilePath))
	}
	if c.Version != "" {
		sb.WriteString(fmt.Sprintf("Compose Version: %s\n", c.Version))
	}
	sb.WriteString(fmt.Sprintf("Total Services: %d\n", len(c.Services)))

	if len(c.Warnings) > 0 {
		sb.WriteString("\nWarnings:\n")
		for _, w := range c.Warnings {
			sb.WriteString(fmt.Sprintf("  - %s\n", w))
		}
	}

	sb.WriteString("\nServices:\n")
	for _, svc := range c.Services {
		sb.WriteString(fmt.Sprintf("  - %s (Line %d)\n", svc.Name, svc.Line))
		if svc.Image != "" {
			sb.WriteString(fmt.Sprintf("      Image: %s\n", svc.Image))
		}
		if svc.HasUser {
			sb.WriteString(fmt.Sprintf("      User: %s (Line %d)\n", svc.User, svc.UserLine))
		}
		if svc.Privileged {
			sb.WriteString(fmt.Sprintf("      Privileged: true (Line %d)\n", svc.PrivilegedLine))
		}
		if len(svc.CapAdd) > 0 {
			sb.WriteString(fmt.Sprintf("      CapAdd: %v (Line %d)\n", svc.CapAdd, svc.CapAddLine))
		}
		if len(svc.CapDrop) > 0 {
			sb.WriteString(fmt.Sprintf("      CapDrop: %v (Line %d)\n", svc.CapDrop, svc.CapDropLine))
		}
		if len(svc.SecurityOpt) > 0 {
			sb.WriteString(fmt.Sprintf("      SecurityOpt: %v (Line %d)\n", svc.SecurityOpt, svc.SecurityOptLine))
		}
		if svc.ReadOnly != nil {
			sb.WriteString(fmt.Sprintf("      ReadOnly: %t (Line %d)\n", *svc.ReadOnly, svc.ReadOnlyLine))
		}
		if len(svc.Volumes) > 0 {
			sb.WriteString(fmt.Sprintf("      Volumes (%d):\n", len(svc.Volumes)))
			for _, v := range svc.Volumes {
				sb.WriteString(fmt.Sprintf("        - %s (Line %d)\n", v.Raw, v.Line))
			}
		}
	}

	return sb.String()
}
