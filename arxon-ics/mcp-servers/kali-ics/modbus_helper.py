#!/usr/bin/env python3
"""Standalone Modbus scanner. Receives parameters via JSON file path argument.
Avoids shell injection risks from inline script generation."""
import json
import sys
from pymodbus.client import ModbusTcpClient

def scan(params):
    target = params["target"]
    port = params.get("port", 502)
    unit_id = params.get("unit_id", 1)
    function = params.get("function", "device_info")
    start_addr = params.get("start_addr", 0)
    count = params.get("count", 10)

    client = ModbusTcpClient(target, port=port)
    client.connect()
    results = {"connected": client.is_socket_open()}

    if client.is_socket_open():
        try:
            if function == "device_info":
                rr = client.read_device_information()
                results["device_info"] = str(rr) if rr else "No response"
            elif function == "read_coils":
                rr = client.read_coils(start_addr, count, slave=unit_id)
                results["coils"] = rr.bits[:count] if not rr.isError() else str(rr)
            elif function == "read_holding":
                rr = client.read_holding_registers(start_addr, count, slave=unit_id)
                results["registers"] = rr.registers if not rr.isError() else str(rr)
            elif function == "read_input":
                rr = client.read_input_registers(start_addr, count, slave=unit_id)
                results["input_registers"] = rr.registers if not rr.isError() else str(rr)
        except Exception as e:
            results["error"] = str(e)

    client.close()
    return results

if __name__ == "__main__":
    params_path = sys.argv[1]
    with open(params_path) as f:
        params = json.load(f)
    print(json.dumps(scan(params)))
