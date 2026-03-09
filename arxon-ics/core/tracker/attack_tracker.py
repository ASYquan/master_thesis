#!/usr/bin/env python3
"""
External ATT&CK for ICS Coverage Tracker.
Does NOT rely on LLM memory. Maintains persistent state of which
techniques have been attempted, succeeded, or skipped.
"""
import json
import os
from datetime import datetime
from typing import Dict, List, Optional

TRACKER_PATH = os.path.expanduser("~/arxon-ics/logs/attack_coverage.json")

# MITRE ATT&CK for ICS Techniques (subset relevant to IoT energy systems)
ICS_TECHNIQUES = {
    "T0800": {"name": "Activate Firmware Update Mode", "tactic": "Persistence"},
    "T0803": {"name": "Block Command Message", "tactic": "Inhibit Response Function"},
    "T0804": {"name": "Block Reporting Message", "tactic": "Inhibit Response Function"},
    "T0806": {"name": "Brute Force I/O", "tactic": "Impair Process Control"},
    "T0807": {"name": "Command-Line Interface", "tactic": "Execution"},
    "T0810": {"name": "Data Historian Compromise", "tactic": "Collection"},
    "T0811": {"name": "Data from Information Repositories", "tactic": "Collection"},
    "T0812": {"name": "Default Credentials", "tactic": "Lateral Movement"},
    "T0813": {"name": "Denial of Control", "tactic": "Impact"},
    "T0814": {"name": "Denial of Service", "tactic": "Impact"},
    "T0816": {"name": "Device Restart/Shutdown", "tactic": "Inhibit Response Function"},
    "T0817": {"name": "Drive-by Compromise", "tactic": "Initial Access"},
    "T0818": {"name": "Engineering Workstation Compromise", "tactic": "Initial Access"},
    "T0819": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "T0820": {"name": "Exploitation for Evasion", "tactic": "Evasion"},
    "T0821": {"name": "Modify Controller Tasking", "tactic": "Execution"},
    "T0822": {"name": "External Remote Services", "tactic": "Initial Access"},
    "T0826": {"name": "Loss of Availability", "tactic": "Impact"},
    "T0827": {"name": "Loss of Control", "tactic": "Impact"},
    "T0829": {"name": "Loss of View", "tactic": "Impact"},
    "T0830": {"name": "Man in the Middle", "tactic": "Collection"},
    "T0831": {"name": "Manipulation of Control", "tactic": "Impact"},
    "T0832": {"name": "Manipulation of View", "tactic": "Impact"},
    "T0836": {"name": "Modify Parameter", "tactic": "Impair Process Control"},
    "T0839": {"name": "Module Firmware", "tactic": "Persistence"},
    "T0842": {"name": "Network Sniffing", "tactic": "Discovery"},
    "T0843": {"name": "Program Download", "tactic": "Lateral Movement"},
    "T0845": {"name": "Program Upload", "tactic": "Collection"},
    "T0846": {"name": "Remote System Discovery", "tactic": "Discovery"},
    "T0847": {"name": "Replication Through Removable Media", "tactic": "Initial Access"},
    "T0848": {"name": "Rogue Master", "tactic": "Initial Access"},
    "T0849": {"name": "Masquerading", "tactic": "Evasion"},
    "T0852": {"name": "Screen Capture", "tactic": "Collection"},
    "T0853": {"name": "Scripting", "tactic": "Execution"},
    "T0855": {"name": "Unauthorized Command Message", "tactic": "Impair Process Control"},
    "T0856": {"name": "Spoof Reporting Message", "tactic": "Evasion"},
    "T0857": {"name": "System Firmware", "tactic": "Persistence"},
    "T0858": {"name": "Change Operating Mode", "tactic": "Execution"},
    "T0859": {"name": "Valid Accounts", "tactic": "Persistence"},
    "T0860": {"name": "Wireless Compromise", "tactic": "Initial Access"},
    "T0862": {"name": "Supply Chain Compromise", "tactic": "Initial Access"},
    "T0863": {"name": "User Execution", "tactic": "Execution"},
    "T0865": {"name": "Spearphishing Attachment", "tactic": "Initial Access"},
    "T0866": {"name": "Exploitation of Remote Services", "tactic": "Lateral Movement"},
    "T0869": {"name": "Standard Application Layer Protocol", "tactic": "Command and Control"},
    "T0871": {"name": "Execution through API", "tactic": "Execution"},
    "T0872": {"name": "Indicator Removal on Host", "tactic": "Evasion"},
    "T0874": {"name": "Hooking", "tactic": "Execution"},
    "T0877": {"name": "I/O Image", "tactic": "Collection"},
    "T0879": {"name": "Damage to Property", "tactic": "Impact"},
    "T0880": {"name": "Loss of Safety", "tactic": "Impact"},
    "T0881": {"name": "Service Stop", "tactic": "Inhibit Response Function"},
    "T0882": {"name": "Theft of Operational Information", "tactic": "Impact"},
    "T0883": {"name": "Change Program State", "tactic": "Execution"},
    "T0884": {"name": "Connection Proxy", "tactic": "Command and Control"},
    "T0885": {"name": "Commonly Used Port", "tactic": "Command and Control"},
    "T0886": {"name": "Remote Services", "tactic": "Lateral Movement"},
    "T0887": {"name": "Wireless Sniffing", "tactic": "Discovery"},
    "T0888": {"name": "Remote System Information Discovery", "tactic": "Discovery"},
    "T0889": {"name": "Modify Program", "tactic": "Persistence"},
    "T0890": {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
    "T0891": {"name": "Hardcoded Credentials", "tactic": "Lateral Movement"},
    "T0893": {"name": "Data Destruction", "tactic": "Inhibit Response Function"},
}


class ATTACKTracker:
    def __init__(self, engagement_id: str, scope_techniques: Optional[List[str]] = None):
        self.engagement_id = engagement_id
        self.scope = scope_techniques or list(ICS_TECHNIQUES.keys())
        self.state = self._load_or_init()

    def _load_or_init(self) -> dict:
        if os.path.exists(TRACKER_PATH):
            with open(TRACKER_PATH) as f:
                all_data = json.load(f)
                if self.engagement_id in all_data:
                    return all_data[self.engagement_id]

        state = {
            "engagement_id": self.engagement_id,
            "created": datetime.utcnow().isoformat(),
            "techniques": {}
        }
        for tid in self.scope:
            if tid in ICS_TECHNIQUES:
                state["techniques"][tid] = {
                    "name": ICS_TECHNIQUES[tid]["name"],
                    "tactic": ICS_TECHNIQUES[tid]["tactic"],
                    "status": "pending",  # pending, attempted, success, failed, skipped, out_of_scope
                    "attempts": [],
                    "findings": []
                }
        return state

    def save(self):
        all_data = {}
        if os.path.exists(TRACKER_PATH):
            with open(TRACKER_PATH) as f:
                all_data = json.load(f)
        all_data[self.engagement_id] = self.state
        os.makedirs(os.path.dirname(TRACKER_PATH), exist_ok=True)
        with open(TRACKER_PATH, 'w') as f:
            json.dump(all_data, f, indent=2)

    def record_attempt(self, technique_id: str, tool: str,
                       success: bool, details: str = ""):
        if technique_id in self.state["techniques"]:
            tech = self.state["techniques"][technique_id]
            tech["attempts"].append({
                "timestamp": datetime.utcnow().isoformat(),
                "tool": tool,
                "success": success,
                "details": details
            })
            if success:
                tech["status"] = "success"
            elif tech["status"] != "success":
                tech["status"] = "attempted"
            self.save()

    def skip_technique(self, technique_id: str, reason: str):
        if technique_id in self.state["techniques"]:
            self.state["techniques"][technique_id]["status"] = "skipped"
            self.state["techniques"][technique_id]["findings"].append({
                "timestamp": datetime.utcnow().isoformat(),
                "note": f"Skipped: {reason}"
            })
            self.save()

    def get_coverage_report(self) -> dict:
        total = len(self.state["techniques"])
        statuses = {}
        for tid, tech in self.state["techniques"].items():
            status = tech["status"]
            statuses.setdefault(status, []).append(tid)

        return {
            "engagement_id": self.engagement_id,
            "total_techniques": total,
            "coverage": {
                status: {"count": len(tids), "techniques": tids}
                for status, tids in statuses.items()
            },
            "coverage_percentage": round(
                (len(statuses.get("success", [])) + len(statuses.get("attempted", [])))
                / total * 100, 1
            ) if total > 0 else 0
        }

    def get_next_techniques(self, n: int = 5) -> list:
        """Return next N pending techniques for the LLM to work on."""
        pending = [
            {"id": tid, **tech}
            for tid, tech in self.state["techniques"].items()
            if tech["status"] == "pending"
        ]
        return pending[:n]
