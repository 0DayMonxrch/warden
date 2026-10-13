package compose

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseComposeServices(t *testing.T) {
	yamlContent := `version: "3.8"
services:
  web:
    image: nginx:alpine
    user: "1000:1000"
    privileged: false
    security_opt:
      - no-new-privileges:true
    read_only: true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./html:/usr/share/nginx/html
    deploy:
      resources:
        limits:
          cpus: "0.50"
          memory: 512M

  db:
    image: postgres:15
    privileged: true
    cap_add:
      - SYS_ADMIN
    cap_drop:
      - ALL
`

	parsed, err := ParseBytes([]byte(yamlContent))
	if err != nil {
		t.Fatalf("unexpected error parsing compose: %v", err)
	}

	if parsed.Version != "3.8" {
		t.Errorf("expected version 3.8, got %q", parsed.Version)
	}

	if len(parsed.Services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(parsed.Services))
	}

	// Service 1: web
	web := parsed.Services[0]
	if web.Name != "web" {
		t.Errorf("expected service 'web', got %q", web.Name)
	}
	if web.Line != 3 {
		t.Errorf("expected web line 3, got %d", web.Line)
	}
	if !web.HasUser || web.User != "1000:1000" {
		t.Errorf("expected user '1000:1000', got %q", web.User)
	}
	if web.Privileged {
		t.Errorf("expected web privileged false, got true")
	}
	if len(web.SecurityOpt) != 1 || web.SecurityOpt[0] != "no-new-privileges:true" {
		t.Errorf("expected security_opt ['no-new-privileges:true'], got %v", web.SecurityOpt)
	}
	if web.ReadOnly == nil || !*web.ReadOnly {
		t.Errorf("expected read_only true")
	}
	if len(web.Volumes) != 2 {
		t.Fatalf("expected 2 volumes, got %d", len(web.Volumes))
	}
	if web.Volumes[0].Source != "/var/run/docker.sock" || !web.Volumes[0].ReadOnly {
		t.Errorf("expected docker.sock ro volume, got %+v", web.Volumes[0])
	}
	if web.Deploy == nil || web.Deploy.Resources == nil || web.Deploy.Resources.Limits == nil {
		t.Fatal("expected deploy resource limits for web")
	}
	if web.Deploy.Resources.Limits.CPUs != "0.50" || web.Deploy.Resources.Limits.Memory != "512M" {
		t.Errorf("unexpected limits: %+v", web.Deploy.Resources.Limits)
	}

	// Service 2: db
	db := parsed.Services[1]
	if db.Name != "db" {
		t.Errorf("expected service 'db', got %q", db.Name)
	}
	if !db.Privileged {
		t.Errorf("expected db privileged true")
	}
	if len(db.CapAdd) != 1 || db.CapAdd[0] != "SYS_ADMIN" {
		t.Errorf("expected cap_add SYS_ADMIN, got %v", db.CapAdd)
	}
	if len(db.CapDrop) != 1 || db.CapDrop[0] != "ALL" {
		t.Errorf("expected cap_drop ALL, got %v", db.CapDrop)
	}
}

func TestComposeJSONAndHumanOutput(t *testing.T) {
	yamlContent := `services:
  app:
    image: myapp:1.0
`
	parsed, err := ParseBytes([]byte(yamlContent))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	jsonOut, err := parsed.ToJSON()
	if err != nil {
		t.Fatalf("failed to format JSON: %v", err)
	}

	var parsedMap map[string]interface{}
	if err := json.Unmarshal([]byte(jsonOut), &parsedMap); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	humanOut := parsed.ToHumanReadable()
	if !strings.Contains(humanOut, "app (Line 2)") {
		t.Errorf("expected human output to mention app, got: %s", humanOut)
	}
}

func TestMalformedComposeYAML(t *testing.T) {
	malformed := `services:
  app: [invalid mapping
`
	_, err := ParseBytes([]byte(malformed))
	if err == nil {
		t.Fatal("expected error parsing malformed YAML, got nil")
	}
}
