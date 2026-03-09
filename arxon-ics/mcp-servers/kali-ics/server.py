#!/usr/bin/env python3
"""
ARXON-ICS MCP Server
Provides ICS penetration testing tools as MCP resources.
Bridges reconnaissance data, ICS protocol tools, and LLM orchestration.
Based on the ARXON pattern from the FortiGate campaign (Feb 2026).
"""

import asyncio
import json
import subprocess
import os
import logging
from typing import Any, Dict, Optional
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s [ARXON] %(levelname)s: %(message)s')
logger = logging.getLogger("arxon-ics")

# ============================================================
# TOOL DEFINITIONS
# Each tool maps to a real penetration testing capability.
# ============================================================

TOOLS = {
    # --- Reconnaissance ---
    "nmap_scan": {
        "description": "Network scan with ICS protocol detection. Supports Modbus, BACnet, EtherNet/IP, DNP3 NSE scripts.",
        "parameters": {
            "target": {"type": "string", "description": "Target IP, range, or CIDR"},
            "scan_type": {"type": "string", "enum": ["quick", "full", "ics", "stealth"], "default": "ics"},
            "ports": {"type": "string", "description": "Port specification (default: ICS common ports)", "default": ""},
            "scripts": {"type": "string", "description": "Additional NSE scripts", "default": ""}
        }
    },
    "mqtt_enumerate": {
        "description": "MQTT broker enumeration. Subscribe to topics, test anonymous access, enumerate clients.",
        "parameters": {
            "broker": {"type": "string", "description": "MQTT broker address"},
            "port": {"type": "integer", "default": 1883},
            "topic": {"type": "string", "default": "#"},
            "duration": {"type": "integer", "description": "Listen duration in seconds", "default": 30},
            "username": {"type": "string", "default": ""},
            "password": {"type": "string", "default": ""}
        }
    },
    "coap_discover": {
        "description": "CoAP resource discovery on target device.",
        "parameters": {
            "target": {"type": "string", "description": "CoAP server address"},
            "port": {"type": "integer", "default": 5683},
            "path": {"type": "string", "default": "/.well-known/core"}
        }
    },
    "modbus_scan": {
        "description": "Modbus TCP enumeration. Read coils, registers, and device identification.",
        "parameters": {
            "target": {"type": "string"},
            "port": {"type": "integer", "default": 502},
            "unit_id": {"type": "integer", "default": 1},
            "function": {"type": "string", "enum": ["read_coils", "read_holding", "read_input", "device_info"], "default": "device_info"},
            "start_addr": {"type": "integer", "default": 0},
            "count": {"type": "integer", "default": 10}
        }
    },
    "nuclei_scan": {
        "description": "Template-based vulnerability scanning with Nuclei. Supports ICS-specific templates.",
        "parameters": {
            "target": {"type": "string"},
            "templates": {"type": "string", "description": "Template tags or paths (e.g., 'ics,scada,iot')", "default": "ics,scada,iot,network"},
            "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"], "default": "medium"}
        }
    },
    "firmware_analyze": {
        "description": "Firmware analysis using binwalk. Extract filesystems, find crypto keys, identify embedded services.",
        "parameters": {
            "firmware_path": {"type": "string", "description": "Path to firmware binary"},
            "extract": {"type": "boolean", "default": True},
            "entropy": {"type": "boolean", "default": False}
        }
    },

    # --- Exploitation ---
    "metasploit_run": {
        "description": "Execute a Metasploit module. SAFETY: Only runs inside Docker executor.",
        "parameters": {
            "module": {"type": "string", "description": "Module path (e.g., exploit/linux/misc/ics_modbus_write)"},
            "options": {"type": "object", "description": "Module options as key-value pairs"},
            "check_only": {"type": "boolean", "default": True, "description": "If true, only check vulnerability without exploiting"}
        }
    },
    "impacket_tool": {
        "description": "Run Impacket tools for Windows/AD enumeration and exploitation. SAFETY: Docker only.",
        "parameters": {
            "tool": {"type": "string", "enum": ["secretsdump", "psexec", "wmiexec", "smbclient", "ntlmrelayx"]},
            "target": {"type": "string"},
            "credentials": {"type": "string", "description": "domain/user:password or hash"},
            "extra_args": {"type": "string", "default": ""}
        }
    },

    # --- Intelligence ---
    "cve_lookup": {
        "description": "Look up CVE details and map to ATT&CK techniques and Nuclei templates.",
        "parameters": {
            "cve_id": {"type": "string", "description": "CVE identifier (e.g., CVE-2023-27532)"},
            "include_nuclei": {"type": "boolean", "default": True}
        }
    },
    "attack_technique_map": {
        "description": "Map ATT&CK for ICS technique to available tools and known CVEs.",
        "parameters": {
            "technique_id": {"type": "string", "description": "ATT&CK technique ID (e.g., T0855)"},
            "target_context": {"type": "string", "description": "Target system description for contextual mapping", "default": ""}
        }
    }
}

# ============================================================
# ICS-SPECIFIC PORT DEFINITIONS
# ============================================================
ICS_PORTS = "20000,44818,47808,502,503,789,1089-1091,1911,2222,2404,4000,4840,4843,4911,9600,19999,20000,34962-34964,34980,55000-55003"

# ============================================================
# TOOL EXECUTION FUNCTIONS
# ============================================================

def run_cmd(cmd: list, timeout: int = 300) -> Dict[str, Any]:
    """Execute a command with timeout and structured output."""
    logger.info(f"Executing: {' '.join(cmd[:5])}...")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": f"Command timed out after {timeout}s"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def execute_nmap_scan(params: Dict) -> Dict:
    target = params["target"]
    scan_type = params.get("scan_type", "ics")
    ports = params.get("ports", "")
    scripts = params.get("scripts", "")

    cmd = ["nmap", "-oX", "-"]

    if scan_type == "quick":
        cmd += ["-sV", "--top-ports", "100"]
    elif scan_type == "full":
        cmd += ["-sV", "-sC", "-O", "-p-"]
    elif scan_type == "ics":
        cmd += ["-sV", "-p", ports or ICS_PORTS,
                "--script", scripts or "modbus-discover,bacnet-info,enip-info,s7-info,iec-identify"]
    elif scan_type == "stealth":
        cmd += ["-sS", "-T2", "-f"]

    cmd.append(target)
    return run_cmd(cmd, timeout=600)


def execute_mqtt_enumerate(params: Dict) -> Dict:
    broker = params["broker"]
    port = params.get("port", 1883)
    topic = params.get("topic", "#")
    duration = params.get("duration", 30)

    results = {}

    # Test anonymous access
    anon_test = run_cmd(["mosquitto_sub", "-h", broker, "-p", str(port),
                         "-t", topic, "-C", "5", "-W", str(min(duration, 10))], timeout=duration + 5)
    results["anonymous_access"] = anon_test

    # If credentials provided, test authenticated access
    if params.get("username"):
        auth_test = run_cmd(["mosquitto_sub", "-h", broker, "-p", str(port),
                             "-u", params["username"], "-P", params.get("password", ""),
                             "-t", topic, "-C", "5", "-W", str(min(duration, 10))], timeout=duration + 5)
        results["authenticated_access"] = auth_test

    # Try to enumerate system topics
    sys_test = run_cmd(["mosquitto_sub", "-h", broker, "-p", str(port),
                        "-t", "$SYS/#", "-C", "20", "-W", "10"], timeout=15)
    results["system_topics"] = sys_test

    return results


def execute_coap_discover(params: Dict) -> Dict:
    target = params["target"]
    port = params.get("port", 5683)
    path = params.get("path", "/.well-known/core")

    return run_cmd(["coap-client", "-m", "get", f"coap://{target}:{port}{path}"], timeout=30)


def execute_modbus_scan(params: Dict) -> Dict:
    """Modbus scan using pymodbus via a standalone helper script.
    Parameters are passed via JSON on stdin to avoid shell injection and quoting issues."""
    import tempfile

    # Write params to temp file (avoids shell quoting issues entirely)
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(params, f)
        params_path = f.name

    helper = os.path.join(os.path.dirname(__file__), "modbus_helper.py")
    result = run_cmd(["python3", helper, params_path], timeout=30)

    try:
        os.unlink(params_path)
    except OSError:
        pass

    return result


def execute_nuclei_scan(params: Dict) -> Dict:
    target = params["target"]
    templates = params.get("templates", "ics,scada,iot,network")
    severity = params.get("severity", "medium")

    cmd = ["nuclei", "-u", target, "-tags", templates,
           "-severity", severity, "-jsonl", "-silent"]
    return run_cmd(cmd, timeout=600)


def execute_firmware_analyze(params: Dict) -> Dict:
    firmware_path = params["firmware_path"]
    extract = params.get("extract", True)
    entropy = params.get("entropy", False)

    results = {}
    if extract:
        results["extraction"] = run_cmd(["binwalk", "-e", firmware_path], timeout=300)
    if entropy:
        results["entropy"] = run_cmd(["binwalk", "-E", firmware_path], timeout=120)
    # Always do signature scan
    results["signatures"] = run_cmd(["binwalk", firmware_path], timeout=120)
    return results


def execute_cve_lookup(params: Dict) -> Dict:
    cve_id = params["cve_id"]
    results = {}

    # Query NVD API
    nvd_result = run_cmd(["curl", "-s",
                          f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"], timeout=30)
    results["nvd"] = nvd_result

    # Check for Nuclei templates
    if params.get("include_nuclei", True):
        nuclei_check = run_cmd(["nuclei", "-tl", "-tags", cve_id.lower().replace("-", "_")], timeout=15)
        results["nuclei_templates"] = nuclei_check

    return results


# Dispatcher
EXECUTORS = {
    "nmap_scan": execute_nmap_scan,
    "mqtt_enumerate": execute_mqtt_enumerate,
    "coap_discover": execute_coap_discover,
    "modbus_scan": execute_modbus_scan,
    "nuclei_scan": execute_nuclei_scan,
    "firmware_analyze": execute_firmware_analyze,
    "cve_lookup": execute_cve_lookup,
}


def handle_tool_call(tool_name: str, params: Dict) -> Dict:
    """Main entry point for tool execution."""
    if tool_name not in EXECUTORS:
        return {"error": f"Unknown tool: {tool_name}"}

    # Sanitize: block dangerous patterns
    param_str = json.dumps(params)
    dangerous = ["rm -rf", "mkfs", "dd if=", "> /dev/", ":(){ :|:", "fork bomb"]
    for pattern in dangerous:
        if pattern in param_str.lower():
            return {"error": f"BLOCKED: Dangerous pattern detected: {pattern}"}

    timestamp = datetime.utcnow().isoformat()
    logger.info(f"Tool call: {tool_name} at {timestamp}")

    result = EXECUTORS[tool_name](params)
    result["tool"] = tool_name
    result["timestamp"] = timestamp

    return result


# ============================================================
# MCP SERVER (using official MCP SDK)
# Handles lifecycle, concurrent connections, and full protocol spec.
# ============================================================

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

app = Server("arxon-ics")


@app.list_tools()
async def list_tools() -> list[Tool]:
    """Register all ICS penetration testing tools."""
    tools = []
    for name, spec in TOOLS.items():
        tools.append(Tool(
            name=name,
            description=spec["description"],
            inputSchema={
                "type": "object",
                "properties": spec["parameters"]
            }
        ))
    return tools


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Execute a tool call through the sanitized dispatcher."""
    result = handle_tool_call(name, arguments)
    return [TextContent(type="text", text=json.dumps(result, indent=2))]


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
