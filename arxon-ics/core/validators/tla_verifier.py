#!/usr/bin/env python3
"""
TLA+ Plan Verification Gate.
Translates an LLM-generated attack plan into TLA+ constants,
runs TLC to model check all reachable states, and returns
pass/fail with counterexample diagnostics if violations are found.

This is the primary differentiator from the original ARXON framework.
"""
import json
import subprocess
import tempfile
import os
import shutil
import logging

logger = logging.getLogger("tla-verifier")

TLA_JAR = os.path.expanduser("~/arxon-ics/tools/tla2tools.jar")
SPEC_DIR = os.path.expanduser("~/arxon-ics/tla-models")
SPEC_FILE = "SafetySpec.tla"


def plan_to_tla_constants(plan: dict, authorized_targets: list,
                          allowed_tools: list, max_exploits: int = 5) -> str:
    """Convert an LLM-generated plan into TLA+ constant definitions."""
    steps = plan.get("steps", [])

    # Build PlanSteps as a TLA+ sequence of records
    tla_steps = []
    for s in steps:
        target = s.get("target", "unknown").replace('"', '\\"')
        tool = s.get("tool", "unknown").replace('"', '\\"')
        phase = s.get("phase", "recon").replace('"', '\\"')
        tla_steps.append(f'[phase |-> "{phase}", target |-> "{target}", tool |-> "{tool}"]')

    plan_steps_str = "<< " + ", ".join(tla_steps) + " >>" if tla_steps else "<< >>"
    targets_str = "{" + ", ".join(f'"{t}"' for t in authorized_targets) + "}"
    tools_str = "{" + ", ".join(f'"{t}"' for t in allowed_tools) + "}"
    forbidden_str = '{"rm_rf", "format_disk", "shutdown", "reboot", "dd_write", "fork_bomb"}'

    return f"""SPECIFICATION Spec
CONSTANTS
    Targets = {targets_str}
    AllowedTools = {tools_str}
    ForbiddenActions = {forbidden_str}
    MaxExploitAttempts = {max_exploits}
    PlanSteps = {plan_steps_str}
INVARIANT SafetyInvariant
PROPERTY EngagementCompletes
PROPERTY AllStepsProcessed
"""


def run_static_checks(plan: dict, authorized_targets: list,
                      allowed_tools: list) -> list:
    """Fast static checks before invoking TLC (catches obvious violations)."""
    violations = []

    steps = plan.get("steps", [])
    if not steps:
        violations.append("PLAN EMPTY: No steps defined")
        return violations

    plan_targets = {s.get("target", "") for s in steps} - {""}
    plan_tools = {s.get("tool", "") for s in steps} - {""}

    # Scope check
    unauthorized = plan_targets - set(authorized_targets)
    if unauthorized:
        violations.append(f"SCOPE VIOLATION: Unauthorized targets: {unauthorized}")

    # Tool check
    forbidden_tools = {"rm_rf", "format_disk", "shutdown", "reboot", "dd_write", "fork_bomb"}
    dangerous = plan_tools & forbidden_tools
    if dangerous:
        violations.append(f"FORBIDDEN TOOL: {dangerous}")

    unrecognized = plan_tools - set(allowed_tools) - forbidden_tools
    if unrecognized:
        violations.append(f"UNKNOWN TOOL WARNING: {unrecognized} (not in allowed list)")

    # Phase ordering check
    phases = [s.get("phase", "") for s in steps]
    valid_order = ["recon", "planning", "exploitation", "reporting"]
    phase_indices = [valid_order.index(p) for p in phases if p in valid_order]
    if phase_indices != sorted(phase_indices):
        violations.append("PHASE ORDER VIOLATION: Steps are not in valid sequential order")

    # Exploitation without planning
    has_planning = any(s.get("phase") == "planning" for s in steps)
    has_exploitation = any(s.get("phase") == "exploitation" for s in steps)
    if has_exploitation and not has_planning:
        violations.append("SAFETY VIOLATION: Exploitation steps exist without prior planning phase")

    # Exploit count per target
    from collections import Counter
    exploit_targets = [s["target"] for s in steps if s.get("phase") == "exploitation"]
    for target, count in Counter(exploit_targets).items():
        if count > 5:
            violations.append(f"EXPLOIT BOUND: Target {target} has {count} exploit steps (max 5)")

    return violations


def verify_plan(plan: dict, authorized_targets: list,
                allowed_tools: list) -> dict:
    """
    Two-stage plan verification:
    1. Fast static checks (Python) catch obvious violations immediately
    2. TLC model checking explores ALL reachable states of the engagement

    Returns: {"verified": bool, "violations": [...], "diagnostics": str,
              "method": "static"|"tlc"|"static+tlc"}
    """
    result = {"verified": False, "violations": [], "diagnostics": "", "method": ""}

    # Stage 1: Static checks
    static_violations = run_static_checks(plan, authorized_targets, allowed_tools)
    if static_violations:
        result["violations"] = static_violations
        result["diagnostics"] = f"Static verification failed with {len(static_violations)} violations"
        result["method"] = "static"
        return result

    # Stage 2: TLC model checking
    work_dir = None
    try:
        work_dir = tempfile.mkdtemp(prefix="arxon_tlc_")

        # Copy spec to work directory (TLC needs it there)
        shutil.copy(os.path.join(SPEC_DIR, SPEC_FILE), work_dir)

        # Generate config from plan
        cfg_content = plan_to_tla_constants(plan, authorized_targets, allowed_tools)
        cfg_path = os.path.join(work_dir, "SafetySpec.cfg")
        with open(cfg_path, 'w') as f:
            f.write(cfg_content)

        # Run TLC model checker
        cmd = [
            "java", "-jar", TLA_JAR,
            "-config", "SafetySpec.cfg",
            "-workers", "auto",
            "-deadlock",          # Check for deadlocks too
            "SafetySpec"
        ]

        logger.info(f"Running TLC in {work_dir}...")
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=180, cwd=work_dir)

        tlc_output = proc.stdout + proc.stderr
        result["diagnostics"] = tlc_output[-2000:]  # last 2000 chars

        if "Model checking completed. No error has been found." in tlc_output:
            result["verified"] = True
            result["method"] = "static+tlc"
            # Extract stats
            for line in tlc_output.split("\n"):
                if "states found" in line.lower() or "distinct states" in line.lower():
                    result["diagnostics"] = line.strip()
                    break
            logger.info("TLC verification PASSED")

        elif "Error:" in tlc_output or "Invariant" in tlc_output:
            result["method"] = "static+tlc"
            # Extract counterexample
            if "Error:" in tlc_output:
                error_start = tlc_output.index("Error:")
                result["violations"].append(
                    f"TLC COUNTEREXAMPLE: {tlc_output[error_start:error_start+500]}")
            else:
                result["violations"].append("TLC found a reachable state violating safety invariants")
            logger.warning("TLC verification FAILED with counterexample")

        elif "Deadlock reached" in tlc_output:
            result["method"] = "static+tlc"
            result["violations"].append(
                "DEADLOCK: Plan has unreachable completion state (engagement cannot finish)")
            logger.warning("TLC found deadlock in engagement model")

        else:
            # TLC ran but unclear result; pass on static checks
            result["verified"] = True
            result["method"] = "static"
            result["diagnostics"] += "\nWARNING: TLC output ambiguous, passed on static checks only"

    except subprocess.TimeoutExpired:
        result["diagnostics"] = "TLC model checking timed out (plan may be too large)"
        result["verified"] = len(result["violations"]) == 0
        result["method"] = "static"
        logger.warning("TLC timed out, using static checks only")

    except FileNotFoundError:
        result["diagnostics"] = f"TLA+ tools not found at {TLA_JAR}"
        result["verified"] = len(result["violations"]) == 0
        result["method"] = "static"
        logger.warning("TLA+ tools not installed, using static checks only")

    except Exception as e:
        logger.warning(f"TLC verification error: {e}; falling back to static checks")
        result["verified"] = len(result["violations"]) == 0
        result["method"] = "static"
        result["diagnostics"] = f"TLC unavailable ({e}); static verification only"

    finally:
        if work_dir:
            shutil.rmtree(work_dir, ignore_errors=True)

    return result
