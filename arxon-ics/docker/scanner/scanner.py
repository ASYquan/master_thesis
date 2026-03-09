#!/usr/bin/env python3
"""
CHECKER2-ICS: Parallel target scanner.
Mirrors CHECKER2's Go-based Docker orchestrator for batch target processing.
"""
import json
import subprocess
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


def scan_target(target: dict) -> dict:
    """Scan a single target for ICS services."""
    ip = target["ip"]
    results = {
        "ip": ip,
        "timestamp": datetime.utcnow().isoformat(),
        "services": [],
        "protocols": []
    }

    # Quick ICS port scan
    ports = "502,1883,5683,4840,47808,20000,44818,2404,9600"
    cmd = ["nmap", "-sV", "-p", ports, "--open", "-oX", "-", ip]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    results["nmap_raw"] = proc.stdout

    # Check for MQTT
    if ":1883" in proc.stdout or target.get("check_mqtt"):
        mqtt_cmd = ["mosquitto_sub", "-h", ip, "-t", "$SYS/#", "-C", "5", "-W", "5"]
        mqtt = subprocess.run(mqtt_cmd, capture_output=True, text=True, timeout=10)
        if mqtt.returncode == 0:
            results["protocols"].append("mqtt")
            results["mqtt_info"] = mqtt.stdout

    # Check for Modbus
    if ":502" in proc.stdout or target.get("check_modbus"):
        results["protocols"].append("modbus")

    # Check for CoAP
    if ":5683" in proc.stdout or target.get("check_coap"):
        results["protocols"].append("coap")

    return results


def main():
    """Read targets from stdin (JSON array), scan in parallel, output results."""
    targets_json = sys.stdin.read()
    targets = json.loads(targets_json)

    max_workers = int(os.environ.get("MAX_WORKERS", "10"))
    results = []

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(scan_target, t): t for t in targets}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                target = futures[future]
                results.append({"ip": target["ip"], "error": str(e)})

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
