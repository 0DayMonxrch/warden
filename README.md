# Warden 🛡️

A lightweight, AST-based static security analyzer for your **Dockerfiles** and **Docker Compose** files, written in Go.

I am building Warden to understand container internals and security engineering from first principles. Instead of relying on brittle regex matching or heavyweight external policy engines, Warden parses input files into typed Abstract Syntax Trees (ASTs) and runs compiled-in Go rules that map directly to real-world container breakout and privilege escalation attack vectors.

---

## Why Warden?

Most simple linters just regex-match strings like `USER` or `privileged`. That breaks on multi-line continuations, multi-stage builds, and nested YAML structures.

Warden takes a compiler-inspired approach:
- **Real Parsers**: Upstream BuildKit (`github.com/moby/buildkit/frontend/dockerfile/parser`) for Dockerfiles, and `gopkg.in/yaml.v3` AST nodes for Compose files to retain exact line numbers.
- **Attack-Driven Rules**: Every single rule exists because it prevents a specific, documented container escape or takeover technique.
- **Zero Runtime Dependencies**: Compiles into a single static Go binary.
- **Deterministic Pipeline**: Every scan validates syntax, exports the parsed AST to `results/parsed-output.json`, and outputs machine-readable JSON alongside human-readable reports with actionable mitigations.

---

## The Rules (v1)

| Rule ID | Severity | Target | Misconfiguration | Concrete Attack Prevented |
| :--- | :--- | :--- | :--- | :--- |
| **`RULE-001`** | `CRITICAL` | `docker-compose.yml` | Exposed Docker Daemon Socket | **Host Takeover via Docker Socket**: Mounting `/var/run/docker.sock` lets a compromised container speak to the host daemon API, spin up privileged containers mounting host root (`/`), and seize full control of the host. |
| **`RULE-002`** | `HIGH` | `Dockerfile`, `docker-compose.yml` | Container Running as Root | **Full Root Impact on Breakout**: Running as UID 0 means any container breakout exploit (e.g., runc CVE-2019-5736 or CVE-2024-21626) gives the attacker root access on the host kernel and filesystem. |
| **`RULE-003`** | `MEDIUM` | `docker-compose.yml` | Unnecessary Linux Capabilities | **Kernel & Namespace Escape**: `privileged: true` or failing to drop capabilities (`cap_drop: [ALL]`) grants `CAP_SYS_ADMIN` or `CAP_NET_RAW`, allowing raw socket manipulation, namespace traversal, and seccomp bypasses. |
| **`RULE-004`** | `MEDIUM` | `docker-compose.yml` | In-Container Privilege Escalation | **SUID/SGID Escalation**: Missing `security_opt: [no-new-privileges:true]` allows attackers inside the container to use setuid binaries (like `sudo` or custom binaries) to escalate to container root. |
| **`RULE-005`** | `HIGH` | `docker-compose.yml` | Missing Resource Limits | **Denial of Service (Host Starvation)**: Unbounded CPU/memory lets runaway processes monopolize resources, starving neighboring containers and triggering the host Linux OOM killer against critical daemons. |
| **`RULE-006`** | `MEDIUM` | `docker-compose.yml` | Writable Root Filesystem | **Malware Persistence**: Without `read_only: true`, an attacker executing code can modify binaries, drop webshells, or tamper with application configs. |

---

## Local Setup & Quickstart

### Prerequisites
- Go 1.26+ (tested on `go1.27.1`)
- Git

### Build
```bash
git clone https://github.com/0DayMonxrch/warden.git
cd warden

# Build the warden CLI binary
go build -o warden ./cmd/warden
```

### Run Tests
```bash
go test -v ./...
```

---

## Usage Examples

Warden comes with sample configurations under [`testdata/`](testdata/) to experiment with:

### 1. Scan a Vulnerable Docker Compose File
```bash
./warden scan testdata/docker-compose.vulnerable.yml
```

**Terminal Output at a Glance:**
```text
================================================================================
                          WARDEN SECURITY SCAN REPORT                           
================================================================================
Target File : testdata/docker-compose.vulnerable.yml
Target Type : docker-compose.yml
Scanned At  : 2026-10-13T05:04:09Z
--------------------------------------------------------------------------------
Summary: 6 findings [CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 0]
================================================================================

[1] [CRITICAL] RULE-001: Exposed Docker Daemon Socket
    Location     : testdata/docker-compose.vulnerable.yml (Line 10)
    Finding      : Service "insecure-app" mounts Docker daemon socket: /var/run/docker.sock:/var/run/docker.sock
    Attack Vector: Mounting the Docker UNIX socket allows any process inside the container to issue API commands to the host Docker daemon, spin up privileged sibling containers mounting host root (/), and compromise the host.
    Mitigation   : Avoid mounting docker.sock. Use a scoped API proxy or eBPF/kernel-based drivers (e.g., Falco) for monitoring.
--------------------------------------------------------------------------------
[2] [HIGH    ] RULE-002: Container Running as Root
    Location     : testdata/docker-compose.vulnerable.yml (Line 6)
    Finding      : Service "insecure-app" does not specify a 'user' directive and runs as root by default
    Attack Vector: Containers running as root (UID 0) possess elevated privileges inside the mount and user namespaces. Any kernel or container runtime escape directly inherits root privileges on the underlying host.
    Mitigation   : Define a non-root user in the Dockerfile using USER instruction or specify user in Docker Compose.
...
```

### 2. Scan a Clean Configuration
```bash
./warden scan testdata/docker-compose.secure.yml
```
```text
Summary: 0 findings [CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0]
✔ No misconfigurations detected. Target configuration meets all security rules.
```

### 3. CI Mode (Pipeline Gating)
In CI mode (`--ci`), Warden returns a non-zero exit code (`1`) whenever violations meet or exceed the configured `--severity-threshold` (default: `HIGH`):
```bash
./warden scan --ci --severity-threshold=HIGH testdata/docker-compose.vulnerable.yml
# Terminal output ends with:
# Error: CI gate failed: findings at or above HIGH severity detected
echo $? # Exits 1
```

### 4. Inspecting the Parsed AST
If you just want to see how Warden decomposes instructions or services:
```bash
# Human-readable stage/instruction tree
./warden parse testdata/Dockerfile.sample

# Structured AST JSON
./warden parse --format=json testdata/docker-compose.secure.yml
```

---

## Output Architecture (`results/`)

Whenever `warden scan` runs, it automatically writes artifacts to the `results/` folder:

```text
results/
├── parsed-output.json    # Normalized AST representation of the input file
├── scan-output.json      # Structured findings with attack vectors & mitigations
└── scan-output.txt       # Human-readable formatted summary table
```

### Sample `scan-output.json` snippet:
```json
{
  "targetFile": "testdata/docker-compose.vulnerable.yml",
  "targetType": "docker-compose.yml",
  "summary": {
    "total": 6,
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 0
  },
  "findings": [
    {
      "ruleId": "RULE-001",
      "ruleName": "Exposed Docker Daemon Socket",
      "severity": "CRITICAL",
      "line": 10,
      "message": "Service \"insecure-app\" mounts Docker daemon socket: /var/run/docker.sock:/var/run/docker.sock",
      "mitigation": "Avoid mounting docker.sock. Use a scoped API proxy or eBPF/kernel-based drivers (e.g., Falco) for monitoring.",
      "attackVector": "Mounting the Docker UNIX socket allows any process inside the container to issue API commands to the host Docker daemon..."
    }
  ]
}
```

---

## Project Structure

```text
warden/
├── cmd/
│   └── warden/             # CLI entrypoint (parse, scan commands with Cobra)
├── pkg/
│   ├── parser/
│   │   ├── compose/        # YAML AST adapter for docker-compose with line attribution
│   │   └── dockerfile/     # BuildKit frontend AST adapter for Dockerfiles
│   ├── report/             # Formatters for CLI, scan-output.json, and scan-output.txt
│   └── rules/              # Compiled-in Rule engine, registry, and checks RULE-001..006
├── rulesets/
│   └── rules.json          # Target ruleset definition & reference
├── testdata/               # Intentionally vulnerable & hardened sample files
├── results/                # Output directory for parsed AST and scan reports
└── go.mod
```

---

## What's In Progress & Roadmap

- [ ] **Kubernetes Manifest Static Analysis**:
  Parsing Pod, Deployment, and DaemonSet specs using upstream `k8s.io/api` types and `sigs.k8s.io/yaml` to check for `hostPID`, `hostNetwork`, privileged security contexts, and root filesystems in orchestrator definitions.
- [ ] **Full Repository / Directory Scanning**:
  Allowing `warden scan .` to recursively discover and scan all Dockerfiles and compose files in a repository.
- [ ] **GitHub Actions Integration**:
  A reusable GitHub Action step to gate pull requests directly in CI workflows with inline PR annotations.
- [ ] **Scan Configuration File (`.warden.yml`)**:
  Support for ignoring specific rules per file/service with documented exception justifications.

---

## License

MIT
