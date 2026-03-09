"""
Hardened Docker execution wrapper.
All exploitation commands run inside isolated containers with:
- Custom network that only routes to target subnets (not host)
- Dropped capabilities
- Read-only root filesystem
- Resource limits
- Non-root user
- Automatic rollback execution on failure
"""
import subprocess
import json
import os
import logging

logger = logging.getLogger("docker-runner")

# Use the isolated network for exploitation, not default bridge
EXPLOIT_NETWORK = "arxon-target-net"
SCAN_NETWORK = "arxon-target-net"


def run_in_executor(command: str, network: str = None,
                    timeout: int = 300, mount_workspace: bool = True,
                    rollback_command: str = None) -> dict:
    """Run a command inside the hardened executor container.
    If the command fails and a rollback_command is provided, execute rollback automatically."""
    workspace = os.path.expanduser("~/arxon-ics/workspace")
    os.makedirs(workspace, exist_ok=True)

    # Default to isolated target network, never default bridge
    if network is None:
        network = EXPLOIT_NETWORK

    cmd = [
        "docker", "run", "--rm",
        f"--network={network}",
        "--cap-drop=ALL",
        "--cap-add=NET_RAW",       # needed for nmap
        "--cap-add=NET_BIND_SERVICE",
        "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=100m",
        "--tmpfs", "/workspace:rw,size=500m",
        "--memory=512m",
        "--cpus=1.0",
        "--pids-limit=100",
        "--security-opt=no-new-privileges",
        "--user", "executor",
    ]

    if mount_workspace:
        cmd += ["-v", f"{workspace}:/data:ro"]

    cmd += ["arxon-executor", "bash", "-c", command]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr
        }

        # Automatic rollback on failure
        if not output["success"] and rollback_command:
            logger.warning(f"Exploit failed, executing rollback: {rollback_command[:80]}...")
            rollback_cmd = cmd[:-1] + [rollback_command]
            try:
                rb = subprocess.run(rollback_cmd, capture_output=True, text=True, timeout=120)
                output["rollback_executed"] = True
                output["rollback_success"] = rb.returncode == 0
                output["rollback_output"] = rb.stdout[:500]
            except Exception as e:
                output["rollback_executed"] = True
                output["rollback_success"] = False
                output["rollback_error"] = str(e)

        return output
    except subprocess.TimeoutExpired:
        # Also attempt rollback on timeout
        if rollback_command:
            logger.warning("Exploit timed out, attempting rollback...")
            try:
                rb_cmd = cmd[:-1] + [rollback_command]
                subprocess.run(rb_cmd, capture_output=True, text=True, timeout=60)
            except Exception:
                pass
        return {"success": False, "error": f"Docker execution timed out after {timeout}s"}


def run_parallel_scan(targets: list, max_workers: int = 10,
                      network: str = None) -> dict:
    """Run CHECKER2-style parallel scanning via Docker."""
    if network is None:
        network = SCAN_NETWORK
    targets_json = json.dumps(targets)

    cmd = [
        "docker", "run", "--rm", "-i",
        f"--network={network}",
        "--cap-drop=ALL",
        "--cap-add=NET_RAW",
        "--memory=1g",
        "--cpus=2.0",
        "-e", f"MAX_WORKERS={max_workers}",
        "arxon-scanner"
    ]

    result = subprocess.run(cmd, input=targets_json,
                            capture_output=True, text=True, timeout=600)

    if result.returncode == 0:
        return json.loads(result.stdout)
    return {"error": result.stderr}
