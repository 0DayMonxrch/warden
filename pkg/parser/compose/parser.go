package compose

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Parse reads Docker Compose content from an io.Reader, parses the YAML AST,
// and constructs a structured ParsedCompose representation.
func Parse(r io.Reader) (*ParsedCompose, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read compose content: %w", err)
	}
	return ParseBytes(data)
}

// ParseBytes parses Docker Compose content from raw bytes.
func ParseBytes(data []byte) (*ParsedCompose, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("failed to parse YAML syntax: %w", err)
	}

	return fromYAMLNode(&root, "")
}

// ParseFile reads and parses a Docker Compose file from the given path.
func ParseFile(path string) (*ParsedCompose, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read compose file at %s: %w", path, err)
	}

	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("failed to parse YAML syntax at %s: %w", path, err)
	}

	return fromYAMLNode(&root, path)
}

func fromYAMLNode(root *yaml.Node, filePath string) (*ParsedCompose, error) {
	if root == nil {
		return nil, fmt.Errorf("empty YAML document")
	}

	// Unwrap document node if present
	docNode := root
	if docNode.Kind == yaml.DocumentNode {
		if len(docNode.Content) == 0 {
			return nil, fmt.Errorf("empty YAML document")
		}
		docNode = docNode.Content[0]
	}

	if docNode.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("expected top-level YAML mapping, got kind %d", docNode.Kind)
	}

	parsed := &ParsedCompose{
		FilePath: filePath,
		RawNode:  root,
	}

	// Iterate top-level mapping keys
	for i := 0; i < len(docNode.Content); i += 2 {
		keyNode := docNode.Content[i]
		valNode := docNode.Content[i+1]

		switch keyNode.Value {
		case "version":
			parsed.Version = valNode.Value
		case "services":
			if valNode.Kind == yaml.MappingNode {
				services, err := parseServices(valNode)
				if err != nil {
					return nil, err
				}
				parsed.Services = services
			}
		}
	}

	return parsed, nil
}

func parseServices(servicesNode *yaml.Node) ([]ServiceConfig, error) {
	var services []ServiceConfig

	for i := 0; i < len(servicesNode.Content); i += 2 {
		keyNode := servicesNode.Content[i]
		valNode := servicesNode.Content[i+1]

		svc := ServiceConfig{
			Name:    keyNode.Value,
			Line:    keyNode.Line,
			RawNode: valNode,
		}

		if valNode.Kind == yaml.MappingNode {
			parseServiceFields(&svc, valNode)
		}

		services = append(services, svc)
	}

	return services, nil
}

func parseServiceFields(svc *ServiceConfig, node *yaml.Node) {
	for i := 0; i < len(node.Content); i += 2 {
		keyNode := node.Content[i]
		valNode := node.Content[i+1]

		switch keyNode.Value {
		case "image":
			svc.Image = valNode.Value

		case "user":
			svc.User = valNode.Value
			svc.UserLine = keyNode.Line
			svc.HasUser = true

		case "privileged":
			svc.Privileged = (valNode.Value == "true")
			svc.PrivilegedLine = keyNode.Line

		case "cap_add":
			svc.CapAdd = parseStringSlice(valNode)
			svc.CapAddLine = keyNode.Line

		case "cap_drop":
			svc.CapDrop = parseStringSlice(valNode)
			svc.CapDropLine = keyNode.Line

		case "security_opt":
			svc.SecurityOpt = parseStringSlice(valNode)
			svc.SecurityOptLine = keyNode.Line

		case "read_only":
			ro := (valNode.Value == "true")
			svc.ReadOnly = &ro
			svc.ReadOnlyLine = keyNode.Line

		case "volumes":
			svc.Volumes = parseVolumes(valNode)

		case "mem_limit":
			svc.MemLimit = valNode.Value

		case "cpus":
			svc.CPUs = valNode.Value

		case "deploy":
			svc.Deploy = parseDeploy(valNode)
		}
	}
}

func parseStringSlice(node *yaml.Node) []string {
	var out []string
	if node.Kind == yaml.SequenceNode {
		for _, child := range node.Content {
			out = append(out, child.Value)
		}
	} else if node.Kind == yaml.ScalarNode && node.Value != "" {
		out = append(out, node.Value)
	}
	return out
}

func parseVolumes(node *yaml.Node) []VolumeMount {
	var mounts []VolumeMount
	if node.Kind != yaml.SequenceNode {
		return mounts
	}

	for _, item := range node.Content {
		if item.Kind == yaml.ScalarNode {
			// Short syntax: "source:target:ro" or "target"
			parts := strings.Split(item.Value, ":")
			m := VolumeMount{
				Raw:  item.Value,
				Line: item.Line,
			}
			if len(parts) >= 2 {
				m.Source = parts[0]
				m.Target = parts[1]
				if len(parts) >= 3 && strings.Contains(parts[2], "ro") {
					m.ReadOnly = true
				}
			} else if len(parts) == 1 {
				m.Target = parts[0]
			}
			mounts = append(mounts, m)
		} else if item.Kind == yaml.MappingNode {
			// Long syntax: type: bind, source: ..., target: ..., read_only: true
			m := VolumeMount{
				Line: item.Line,
			}
			for i := 0; i < len(item.Content); i += 2 {
				k := item.Content[i].Value
				v := item.Content[i+1].Value
				switch k {
				case "source":
					m.Source = v
				case "target":
					m.Target = v
				case "read_only":
					m.ReadOnly = (v == "true")
				}
			}
			m.Raw = fmt.Sprintf("%s:%s", m.Source, m.Target)
			mounts = append(mounts, m)
		}
	}

	return mounts
}

func parseDeploy(node *yaml.Node) *DeployConfig {
	if node.Kind != yaml.MappingNode {
		return nil
	}

	deploy := &DeployConfig{}
	for i := 0; i < len(node.Content); i += 2 {
		k := node.Content[i].Value
		v := node.Content[i+1]
		if k == "resources" && v.Kind == yaml.MappingNode {
			deploy.Resources = parseResources(v)
		}
	}
	return deploy
}

func parseResources(node *yaml.Node) *ResourceConfig {
	rc := &ResourceConfig{}
	for i := 0; i < len(node.Content); i += 2 {
		k := node.Content[i].Value
		v := node.Content[i+1]
		if k == "limits" && v.Kind == yaml.MappingNode {
			rc.Limits = parseResourceLimits(v, node.Content[i].Line)
		}
	}
	return rc
}

func parseResourceLimits(node *yaml.Node, line int) *ResourceLimits {
	limits := &ResourceLimits{Line: line}
	for i := 0; i < len(node.Content); i += 2 {
		k := node.Content[i].Value
		v := node.Content[i+1].Value
		switch k {
		case "cpus":
			limits.CPUs = v
		case "memory":
			limits.Memory = v
		case "pids":
			if p, err := strconv.ParseInt(v, 10, 64); err == nil {
				limits.Pids = p
			}
		}
	}
	return limits
}
