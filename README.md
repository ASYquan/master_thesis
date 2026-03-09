# ARXON-ICS: LLM-Orchestrated ICS Penetration Testing Framework

Master's thesis project, University of Oslo. An automated penetration testing
framework for Industrial Control Systems (ICS) and Cyber-Physical Systems (CPS)
in the energy sector, based on the ARXON/CHECKER2 attack pattern (FortiGate
campaign, February 2026).

The framework adapts a real-world multi-model attack pipeline into a
safety-verified, ICS-focused orchestration system for authorized security
assessments.

## Development Models

This thesis explores multiple approaches to LLM-assisted penetration testing.
Three models have been developed and evaluated:

1. **Claude Code on Kali VM** (`claude-code-kali/`): Running Claude Code
   directly on the Kali Linux VM as an interactive penetration testing
   assistant. Claude Code operates in the terminal with full access to Kali
   tools, enabling real-time reconnaissance, exploitation, and analysis.
   Includes the bootstrap setup script.

2. **Kali MCP Server with Claude Desktop** (`mcp-kali-server/`): A standalone
   MCP server (`kali_server.py` and `mcp_server.py`) that exposes Kali Linux
   penetration testing tools to Claude Desktop via the Model Context Protocol.
   This allows Claude Desktop to drive nmap, Metasploit, Modbus, MQTT, and
   other tools remotely through a structured tool interface. Configuration is
   in `mcp-kali-server.json`.

3. **ARXON-ICS Orchestrator** (`arxon-ics/`): The multi-model framework
   described below, which coordinates DeepSeek, Kimi K2.5, Claude, and local
   models through a swarm architecture with TLA+ safety verification.

## Motivation

Critical infrastructure in the energy sector relies on Cyber-Physical Systems
that combine IT and OT networks with thousands of interconnected devices. The
attack surface is enormous, and manual penetration testing is time-consuming
and expensive. This framework automates the discovery of known vulnerabilities,
misconfigurations, and protocol weaknesses so that human testers can focus on
finding zero-day threats.

## Architecture

```
ARXON-ICS ORCHESTRATOR (Python swarm coordinator)

  PHASE 1: Recon    -->  PHASE 2: Planning  -->  PHASE 3: Exploit  -->  PHASE 4: Report
  (DeepSeek-chat)        (DeepSeek-reasoner)     (Kimi K2.5 +           (DeepSeek-chat)
                               |                  Claude)
                          TLA+ VERIFY
                          (safety gate)

  SHARED INFRASTRUCTURE:
  - RAG Knowledge Base (ChromaDB)
  - ATT&CK for ICS Coverage Tracker
  - MCP Server (ICS tools: Modbus, MQTT, CoAP, Nuclei, nmap)
  - claude-code-router (multi-model routing)

  EXECUTION LAYER:
  - CHECKER2-ICS Parallel Scanner (Docker)
  - Kimi Code CLI Agent (K2.5 native)
  - Hardened Docker Executor (isolated, read-only, non-root)
```

### Model Routing

The orchestrator routes tasks to different LLMs based on their strengths:

- **DeepSeek-chat**: Reconnaissance coordination and reporting (fast, cheap)
- **DeepSeek-reasoner**: Strategic attack planning and path generation
- **Kimi K2.5**: Code generation, exploit development, task decomposition
- **Claude**: Vulnerability assessment and complex reasoning
- **Gemini Flash**: Long-context processing (via router)
- **Ollama (local)**: Background tasks and fallback

A custom semantic router (`arxon-router.js`) inspects request content and
routes to the appropriate model automatically.

### Safety Verification

Unlike the original ARXON campaign (which had zero safety gates), this
framework includes a TLA+ verification layer:

1. **Static checks** (Python): Catches scope violations, forbidden tools,
   phase ordering issues, and exploit count bounds immediately.
2. **TLC model checking** (TLA+): Exhaustively explores all reachable states
   of the engagement plan to prove that safety invariants hold before any
   exploitation proceeds.

The TLA+ specification models the engagement as a state machine with Init,
Next, and temporal properties. Key invariants:

- Exploitation never happens without prior plan verification
- Exploit attempt counts never exceed configured bounds per target
- No step executes against unauthorized targets
- No forbidden action ever runs
- The engagement eventually reaches completion (liveness)

## Directory Structure

```
arxon-ics/
  core/
    orchestrator/
      arxon.py                  Main orchestrator (swarm coordinator)
    validators/
      tla_verifier.py           TLA+ verification gate (static + TLC)
    tracker/
      attack_tracker.py         ATT&CK for ICS coverage tracker
    rag.py                      RAG knowledge base (ChromaDB)
    docker_runner.py            Hardened Docker execution with rollback
    cost_tracker.py             Per-model per-phase token and cost tracking
    comms.py                    Inter-model message protocol
  mcp-servers/
    kali-ics/
      server.py                 MCP server (ICS tools)
      modbus_helper.py          Standalone Modbus scanner
  docker/
    executor/
      Dockerfile                Hardened exploitation container
    scanner/
      Dockerfile                CHECKER2-style parallel scanner
      scanner.py                Parallel target scanning script
  tla-models/
    SafetySpec.tla              TLA+ safety specification
  config/
    kimi-mcp.json               Kimi Code MCP configuration
  knowledge/                    Static knowledge files (TLA+, CACAO, CVE maps)
  logs/                         Engagement logs and cost tracking
  workspace/                    Shared workspace for Docker mounts
```

## Prerequisites

- Kali Linux (tested on 6.x)
- Python 3.11+
- Docker
- Java (for TLA+ tools)
- Node.js and npm
- API keys for: OpenRouter, DeepSeek, Moonshot (Kimi K2.5)

### System Packages

```bash
sudo apt install -y \
    nodejs npm docker.io docker-compose \
    python3 python3-pip python3-venv \
    nmap metasploit-framework \
    mosquitto-clients libcoap3-bin \
    python3-pymodbus binwalk nuclei \
    default-jre
```

### Python Environment

```bash
cd ~/arxon-ics
python3 -m venv venv
source venv/bin/activate

pip install \
    chromadb sentence-transformers \
    pymodbus aiocoap paho-mqtt \
    requests aiohttp pyyaml jsonschema \
    rich typer openai anthropic mcp tiktoken
```

### Agent Tools

```bash
npm install -g @anthropic-ai/claude-code
npm install -g @musistudio/claude-code-router

# TLA+ model checker
wget https://github.com/tlaplus/tlaplus/releases/latest/download/tla2tools.jar \
    -O ~/arxon-ics/tools/tla2tools.jar
```

### API Keys

```bash
cat > ~/.arxon-env << 'EOF'
export OPENROUTER_API_KEY="your-openrouter-key"
export DEEPSEEK_API_KEY="your-deepseek-key"
export MOONSHOT_API_KEY="your-moonshot-key"
EOF

chmod 600 ~/.arxon-env
echo 'source ~/.arxon-env' >> ~/.bashrc
source ~/.arxon-env
```

## Setup

### 1. Configure claude-code-router

Copy the router configuration files:

```bash
mkdir -p ~/.claude-code-router
# Copy config.json and arxon-router.js from this repo
# or use ccr to generate defaults and modify
```

### 2. Build Docker Images

```bash
cd ~/arxon-ics/docker/executor && docker build -t arxon-executor .
cd ~/arxon-ics/docker/scanner && docker build -t arxon-scanner .

# Create isolated Docker network
docker network create \
    --driver bridge \
    --subnet=172.30.0.0/16 \
    arxon-target-net

# Block containers from reaching the host
sudo iptables -I DOCKER-USER -s 172.30.0.0/16 -d 172.30.0.1 -j DROP
sudo iptables -I DOCKER-USER -s 172.30.0.0/16 -d 172.30.0.0/16 -j ACCEPT
```

### 3. Register MCP Server

Add to `~/.claude.json`:

```json
{
  "mcpServers": {
    "arxon-ics": {
      "command": "python3",
      "args": ["/home/kali/arxon-ics/mcp-servers/kali-ics/server.py"]
    }
  }
}
```

### 4. Initialize Knowledge Base

```bash
cd ~/arxon-ics
source venv/bin/activate
python3 -c "from core.rag import KnowledgeBase; kb = KnowledgeBase(); kb.ingest_knowledge_dir()"
```

## Usage

### Running an Engagement

```bash
cd ~/arxon-ics
source venv/bin/activate

# Start the router
ccr start

# Run the orchestrator
python3 core/orchestrator/arxon.py \
    192.168.1.0/24 \
    --objective "Assess ICS security posture of IoT energy monitoring system" \
    --techniques T0812 T0819 T0855 T0859 \
    --ingest-knowledge
```

### Command-line Arguments

```
positional arguments:
  targets               Target IPs or ranges

options:
  -o, --objective       Engagement objective (required)
  -e, --engagement-id   Custom engagement ID
  -t, --techniques      ATT&CK technique IDs to focus on
  --ingest-knowledge    Ingest knowledge base before starting
```

### Engagement Flow

1. **Reconnaissance**: K2.5 decomposes the recon task into parallel subtasks.
   CHECKER2-style Docker scanning runs alongside LLM-coordinated enumeration.
   DeepSeek-chat synthesizes results into a structured report.

2. **Attack Planning**: DeepSeek-reasoner generates a structured attack plan
   with MITRE ATT&CK for ICS technique mappings, rollback procedures, and
   risk levels for each step.

3. **TLA+ Verification**: The plan passes through static Python checks and
   TLC model checking. If violations are found, DeepSeek-reasoner attempts
   to fix the plan automatically. If verification fails twice, the engagement
   aborts.

4. **Exploitation**: Kimi Code CLI drives MCP tools natively (preferred mode)
   or K2.5 generates exploit code via API for execution in hardened Docker
   containers. Failed exploits trigger automatic rollback using plan-defined
   procedures.

5. **Reporting**: DeepSeek-chat generates a structured report with findings
   by severity, ATT&CK coverage statistics, and recommendations. Results
   are stored in the RAG knowledge base to improve future engagements.

### Output

Each engagement produces:

- Structured JSON engagement log in `~/arxon-ics/logs/`
- Per-model cost tracking in `~/arxon-ics/logs/cost_tracking.jsonl`
- ATT&CK coverage state in `~/arxon-ics/logs/attack_coverage.json`
- RAG entries in the ChromaDB knowledge base

## MCP Tools

The MCP server exposes the following tools:

| Tool | Description |
|------|-------------|
| `nmap_scan` | Network scan with ICS protocol detection (Modbus, BACnet, EtherNet/IP, DNP3) |
| `mqtt_enumerate` | MQTT broker enumeration, anonymous access testing, topic discovery |
| `coap_discover` | CoAP resource discovery |
| `modbus_scan` | Modbus TCP enumeration (coils, registers, device identification) |
| `nuclei_scan` | Template-based vulnerability scanning with ICS/SCADA/IoT tags |
| `firmware_analyze` | Firmware analysis with binwalk (extraction, entropy, signatures) |
| `metasploit_run` | Metasploit module execution (Docker-isolated, check-only by default) |
| `impacket_tool` | Impacket tools for Windows/AD enumeration (Docker-isolated) |
| `cve_lookup` | CVE detail lookup with NVD API and Nuclei template mapping |
| `attack_technique_map` | Map ATT&CK for ICS techniques to available tools and CVEs |

## Security Controls

- All exploitation runs inside Docker containers with dropped capabilities,
  read-only root filesystems, resource limits, and non-root users
- Docker containers run on an isolated network that cannot reach the host
- TLA+ verification is mandatory before any exploitation proceeds
- Dangerous command patterns are blocked at the MCP server level
- API keys are stored in environment variables, never in code
- Engagement logs are append-only for audit trail integrity

## Thesis Measurement Hooks

The framework is instrumented for thesis evaluation:

- **RQ1 (Vulnerability Discovery)**: ATT&CK technique coverage percentage,
  unique CVEs discovered per engagement
- **RQ2 (Human Interaction Reduction)**: Human interventions per engagement,
  time from start to report with zero human input
- **RQ3 (IoT Protocol Support)**: Protocol coverage across MQTT, CoAP,
  Modbus, BLE, and Zigbee; tool execution success rate per protocol
- **Cost analysis**: Per-model, per-phase token usage and estimated cost
  in USD, enabling comparison of multi-model vs single-model approaches

## TODO

- Integrate the Ghidra decompiler tool (see `ghidra-decompiler` repo) with
  the Python-based Argus reconnaissance tool to streamline firmware reverse
  engineering and automated vulnerability discovery in a single pipeline.
- Waiting for Moonshot to implement Kimi K2.5's agentic swarm capabilities
  in its CLI tool, or to expose CLI-level usage that supports autonomous
  multi-step tool execution. Once available, the ARXON-ICS orchestrator can
  leverage K2.5's native task decomposition directly through the CLI rather
  than relying on the API-based fallback path.

## License

Academic research use only. University of Oslo, 2026.
