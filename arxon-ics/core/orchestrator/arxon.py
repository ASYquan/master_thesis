#!/usr/bin/env python3
"""
ARXON-ICS Orchestrator
======================
Multi-model swarm coordinator for ICS penetration testing.
Adapts the ARXON/CHECKER2 pattern (FortiGate campaign, Feb 2026)
with TLA+ safety verification and ATT&CK for ICS coverage tracking.

Model Routing (mirrors ARXON's dual-model split):
- DeepSeek-reasoner: Strategic planning, attack path generation
- DeepSeek-chat: Reconnaissance coordination, reporting, cost-effective tasks
- Kimi K2.5: Code generation, exploit development, task decomposition (swarm)
- Claude: Vulnerability assessment, complex reasoning (via router)
- Gemini Flash: Long context processing (via router longContext)
- Ollama local: Background tasks, fallback

Communication flow:
  Orchestrator -> claude-code-router -> appropriate model
  Orchestrator -> Kimi Code CLI (direct, for agentic execution)
  Orchestrator -> Docker containers (for isolated execution)
  All results -> RAG knowledge base (growing per engagement)
"""

import os
import sys
import json
import asyncio
import logging
import subprocess
import time
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed

# Add parent directory to path
sys.path.insert(0, os.path.expanduser("~/arxon-ics"))
sys.path.insert(0, os.path.expanduser("~/arxon-ics/core"))

from core.rag import KnowledgeBase
from core.tracker.attack_tracker import ATTACKTracker
from core.validators.tla_verifier import verify_plan
from core.docker_runner import run_in_executor, run_parallel_scan
from core.cost_tracker import CostTracker

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [ARXON-%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.path.expanduser("~/arxon-ics/logs/arxon.log"))
    ]
)
logger = logging.getLogger("arxon")


class LLMClient:
    """Unified client for calling models through claude-code-router or directly.
    All calls are instrumented with cost tracking for thesis analysis."""

    def __init__(self, router_url: str = "http://127.0.0.1:3456",
                 cost_tracker: CostTracker = None):
        self.router_url = router_url
        self.deepseek_key = os.environ.get("DEEPSEEK_API_KEY", "")
        self.moonshot_key = os.environ.get("MOONSHOT_API_KEY", "")
        self.openrouter_key = os.environ.get("OPENROUTER_API_KEY", "")
        self.costs = cost_tracker

    def _track(self, model: str, phase: str, prompt: str,
               response: str, latency_ms: int, success: bool):
        """Record token usage and cost for this call."""
        if self.costs:
            input_tokens = self.costs.estimate_tokens(prompt)
            output_tokens = self.costs.estimate_tokens(response or "")
            self.costs.record(model, phase, input_tokens, output_tokens,
                              latency_ms, success)

    def call_via_router(self, prompt: str, system: str = "",
                        route_hint: str = "") -> Optional[str]:
        """Call a model through claude-code-router (used for Claude Code integration)."""
        import requests

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        if route_hint:
            prompt = f"/model {route_hint}\n{prompt}"
        messages.append({"role": "user", "content": prompt})

        try:
            resp = requests.post(
                f"{self.router_url}/v1/chat/completions",
                json={
                    "model": "default",
                    "messages": messages,
                    "max_tokens": 8192,
                    "temperature": 0.7
                },
                headers={"Content-Type": "application/json"},
                timeout=600
            )
            data = resp.json()
            return data["choices"][0]["message"]["content"]
        except Exception as e:
            logger.error(f"Router call failed: {e}")
            return None

    def call_deepseek(self, prompt: str, system: str = "",
                      model: str = "deepseek-chat",
                      phase: str = "unknown") -> Optional[str]:
        """Direct DeepSeek API call (bypasses router for reliability)."""
        import requests

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        t0 = time.time()
        try:
            resp = requests.post(
                "https://api.deepseek.com/chat/completions",
                json={"model": model, "messages": messages, "max_tokens": 8192},
                headers={
                    "Authorization": f"Bearer {self.deepseek_key}",
                    "Content-Type": "application/json"
                },
                timeout=600
            )
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            latency = int((time.time() - t0) * 1000)
            self._track(model, phase, prompt, content, latency, True)
            return content
        except Exception as e:
            latency = int((time.time() - t0) * 1000)
            self._track(model, phase, prompt, "", latency, False)
            logger.error(f"DeepSeek call failed: {e}")
            return None

    def call_kimi(self, prompt: str, system: str = "",
                  thinking: bool = True, phase: str = "unknown") -> Optional[str]:
        """Direct Kimi K2.5 API call via Moonshot or OpenRouter."""
        import requests

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        # Try Moonshot API first
        if self.moonshot_key:
            try:
                resp = requests.post(
                    "https://api.moonshot.cn/v1/chat/completions",
                    json={
                        "model": "kimi-k2.5",
                        "messages": messages,
                        "max_tokens": 16384,
                        "temperature": 1.0 if thinking else 0.6
                    },
                    headers={
                        "Authorization": f"Bearer {self.moonshot_key}",
                        "Content-Type": "application/json"
                    },
                    timeout=600
                )
                data = resp.json()
                return data["choices"][0]["message"]["content"]
            except Exception as e:
                logger.warning(f"Moonshot API failed ({e}), falling back to OpenRouter")

        # Fallback to OpenRouter
        if self.openrouter_key:
            try:
                resp = requests.post(
                    "https://openrouter.ai/api/v1/chat/completions",
                    json={
                        "model": "moonshotai/kimi-k2.5",
                        "messages": messages,
                        "max_tokens": 16384
                    },
                    headers={
                        "Authorization": f"Bearer {self.openrouter_key}",
                        "Content-Type": "application/json"
                    },
                    timeout=600
                )
                data = resp.json()
                return data["choices"][0]["message"]["content"]
            except Exception as e:
                logger.error(f"OpenRouter K2.5 call failed: {e}")

        return None

    def call_kimi_cli(self, task: str, cwd: str = None) -> Optional[str]:
        """Execute a task via Kimi Code CLI (uses K2.5 natively with MCP tools)."""
        cmd = ["kimi", "--no-interactive", "-m", task]
        if cwd:
            cmd = ["kimi", "--no-interactive", "--cwd", cwd, "-m", task]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            return result.stdout if result.returncode == 0 else result.stderr
        except Exception as e:
            logger.error(f"Kimi CLI call failed: {e}")
            return None


class SwarmDecomposer:
    """
    Uses K2.5's trained task decomposition ability to break complex tasks
    into parallel subtasks. This is the DIY swarm implementation.
    """

    def __init__(self, llm: LLMClient):
        self.llm = llm

    def decompose(self, task: str, context: str = "") -> List[Dict]:
        """
        Ask K2.5 to decompose a task into parallel subtasks.
        Returns list of {id, description, dependencies, model_hint, parallel_group}
        """
        system = """You are a task decomposition agent for ICS penetration testing.
Given a complex task, break it into subtasks that can be executed in parallel where possible.

Output ONLY valid JSON array. Each subtask object must have:
- "id": unique string identifier
- "description": what to do
- "dependencies": array of subtask IDs that must complete first (empty for independent tasks)
- "parallel_group": integer grouping tasks that can run simultaneously
- "model_hint": "deepseek-reasoner" for planning, "kimi-k2.5" for code/exploit, "deepseek-chat" for recon/reporting
- "tool_hint": which MCP tool to use if applicable (e.g., "nmap_scan", "mqtt_enumerate")
- "estimated_duration": "short" (<1min), "medium" (1-5min), "long" (>5min)

Maximize parallelism. Group independent tasks in the same parallel_group.
NEVER skip the planning phase before exploitation."""

        prompt = f"""Decompose this ICS penetration testing task into parallel subtasks:

TASK: {task}

CONTEXT:
{context[:4000] if context else "No prior context available."}

Output JSON array only. No explanation."""

        response = self.llm.call_kimi(prompt, system=system, thinking=True)
        if not response:
            return [{"id": "fallback_0", "description": task,
                     "dependencies": [], "parallel_group": 0,
                     "model_hint": "deepseek-chat", "tool_hint": "",
                     "estimated_duration": "medium"}]

        # Parse JSON from response
        try:
            # Handle markdown code blocks
            clean = response.strip()
            if "```json" in clean:
                clean = clean.split("```json")[1].split("```")[0]
            elif "```" in clean:
                clean = clean.split("```")[1].split("```")[0]
            return json.loads(clean)
        except json.JSONDecodeError:
            logger.warning("K2.5 decomposition returned invalid JSON, using fallback")
            return [{"id": "fallback_0", "description": task,
                     "dependencies": [], "parallel_group": 0,
                     "model_hint": "deepseek-chat", "tool_hint": "",
                     "estimated_duration": "medium"}]


class ARXONOrchestrator:
    """
    Main orchestrator. Coordinates the full engagement lifecycle.
    """

    def __init__(self, engagement_id: str = None):
        self.engagement_id = engagement_id or f"eng_{int(time.time())}"
        self.cost_tracker = CostTracker(self.engagement_id)
        self.llm = LLMClient(cost_tracker=self.cost_tracker)
        self.swarm = SwarmDecomposer(self.llm)
        self.rag = KnowledgeBase()
        self.tracker = None  # ATT&CK tracker, initialized per engagement
        self.log_path = os.path.expanduser(
            f"~/arxon-ics/logs/{self.engagement_id}.json")
        self.engagement_log = []

        # Ensure router is running
        subprocess.run(["ccr", "start"], capture_output=True)

        logger.info(f"ARXON-ICS Orchestrator initialized: {self.engagement_id}")

    def _log(self, phase: str, action: str, data: Any):
        """Append to engagement log."""
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "phase": phase,
            "action": action,
            "data": data if isinstance(data, (str, dict, list)) else str(data)
        }
        self.engagement_log.append(entry)
        with open(self.log_path, 'w') as f:
            json.dump(self.engagement_log, f, indent=2)

    def _execute_subtask(self, subtask: dict, context: str = "") -> dict:
        """Execute a single subtask using the appropriate model/tool."""
        model = subtask.get("model_hint", "deepseek-chat")
        tool = subtask.get("tool_hint", "")
        desc = subtask["description"]

        logger.info(f"  Executing subtask [{subtask['id']}]: {desc[:80]}...")

        result = {"subtask_id": subtask["id"], "status": "failed", "output": ""}

        try:
            if tool:
                # Direct MCP tool execution
                from mcp_servers.kali_ics.server import handle_tool_call
                tool_result = handle_tool_call(tool, {"target": desc})
                result["output"] = json.dumps(tool_result)
                result["status"] = "success" if tool_result.get("success") else "partial"

            elif model == "kimi-k2.5":
                output = self.llm.call_kimi(
                    f"{desc}\n\nContext:\n{context[:3000]}",
                    system="You are an ICS penetration testing expert. Execute the given task precisely."
                )
                result["output"] = output or "No response"
                result["status"] = "success" if output else "failed"

            elif model == "deepseek-reasoner":
                output = self.llm.call_deepseek(
                    f"{desc}\n\nContext:\n{context[:3000]}",
                    system="You are a strategic ICS security analyst. Provide detailed analysis.",
                    model="deepseek-reasoner"
                )
                result["output"] = output or "No response"
                result["status"] = "success" if output else "failed"

            else:  # deepseek-chat or default
                output = self.llm.call_deepseek(
                    f"{desc}\n\nContext:\n{context[:3000]}",
                    system="You are an ICS penetration testing assistant.",
                    model="deepseek-chat"
                )
                result["output"] = output or "No response"
                result["status"] = "success" if output else "failed"

        except Exception as e:
            result["output"] = f"Error: {e}"
            result["status"] = "error"

        return result

    def _execute_parallel_group(self, subtasks: List[dict],
                                context: str = "",
                                max_retries: int = 1) -> List[dict]:
        """Execute a group of subtasks in parallel (the swarm).
        If more than half the group fails, ask K2.5 to re-analyze and
        propose alternative subtasks (retry-with-redecomposition)."""
        results = []
        with ThreadPoolExecutor(max_workers=min(len(subtasks), 8)) as pool:
            futures = {
                pool.submit(self._execute_subtask, st, context): st
                for st in subtasks
            }
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as e:
                    st = futures[future]
                    results.append({
                        "subtask_id": st["id"],
                        "status": "error",
                        "output": str(e)
                    })

        # Retry-with-redecomposition: if majority failed, ask K2.5 to adapt
        failed = [r for r in results if r["status"] in ("failed", "error")]
        if len(failed) > len(subtasks) / 2 and max_retries > 0:
            logger.warning(
                f"  {len(failed)}/{len(subtasks)} subtasks failed. "
                f"Re-decomposing with K2.5 ({max_retries} retries left)..."
            )
            failure_context = json.dumps([
                {"id": r["subtask_id"], "error": r["output"][:300]}
                for r in failed
            ])
            retry_prompt = (
                f"These subtasks failed:\n{failure_context}\n\n"
                f"Original context:\n{context[:2000]}\n\n"
                f"Propose alternative approaches for the failed tasks. "
                f"Output JSON array of replacement subtasks."
            )
            retry_output = self.llm.call_kimi(
                retry_prompt,
                system="You are a task re-planner. Analyze failures and propose alternatives.",
                phase="retry"
            )
            if retry_output:
                try:
                    clean = retry_output.strip()
                    if "```json" in clean:
                        clean = clean.split("```json")[1].split("```")[0]
                    new_subtasks = json.loads(clean)
                    retry_results = self._execute_parallel_group(
                        new_subtasks, context, max_retries=max_retries - 1)
                    results.extend(retry_results)
                except (json.JSONDecodeError, IndexError):
                    logger.warning("  Re-decomposition produced invalid JSON, skipping retry")

        return results

    # ================================================================
    # ENGAGEMENT PHASES
    # ================================================================

    def phase_recon(self, targets: List[str], objective: str) -> dict:
        """
        Phase 1: Reconnaissance
        Uses CHECKER2-style parallel scanning + K2.5 decomposition.
        """
        logger.info("=" * 60)
        logger.info("PHASE 1: RECONNAISSANCE")
        logger.info("=" * 60)

        # Step 1: K2.5 decomposes the recon task
        task = f"Perform comprehensive ICS reconnaissance on targets: {', '.join(targets)}. Objective: {objective}"
        rag_context = self.rag.get_relevant_context(task)
        subtasks = self.swarm.decompose(task, context=rag_context)

        logger.info(f"  Decomposed into {len(subtasks)} subtasks")
        self._log("recon", "decomposition", subtasks)

        # Step 2: Execute subtasks by parallel group
        all_results = []
        groups = {}
        for st in subtasks:
            g = st.get("parallel_group", 0)
            groups.setdefault(g, []).append(st)

        accumulated_context = rag_context
        for group_id in sorted(groups.keys()):
            group = groups[group_id]
            logger.info(f"  Executing parallel group {group_id} ({len(group)} tasks)")
            results = self._execute_parallel_group(group, accumulated_context)
            all_results.extend(results)

            # Accumulate context for dependent tasks
            for r in results:
                if r["status"] == "success":
                    accumulated_context += f"\n\n{r['output'][:2000]}"

        # Step 3: CHECKER2-style parallel Docker scan (for raw port scanning)
        logger.info("  Running CHECKER2 parallel scan...")
        docker_targets = [{"ip": t} for t in targets]
        checker2_results = run_parallel_scan(docker_targets)
        all_results.append({
            "subtask_id": "checker2_scan",
            "status": "success",
            "output": json.dumps(checker2_results)
        })

        self._log("recon", "results", all_results)

        # Step 4: Synthesize recon results using DeepSeek
        synthesis_prompt = f"""Synthesize these ICS reconnaissance results into a structured report.

Targets: {', '.join(targets)}
Objective: {objective}

Raw Results:
{json.dumps(all_results, indent=2)[:6000]}

Output a JSON object with:
- "discovered_hosts": list of hosts with open ports and services
- "ics_protocols": list of ICS protocols detected (Modbus, MQTT, CoAP, etc.)
- "potential_vulns": list of potential vulnerabilities
- "attack_surface": summary of the attack surface
- "recommended_techniques": list of ATT&CK for ICS technique IDs to investigate"""

        synthesis = self.llm.call_deepseek(synthesis_prompt, model="deepseek-chat")
        self._log("recon", "synthesis", synthesis)

        return {"raw": all_results, "synthesis": synthesis}

    def phase_planning(self, recon_results: dict,
                       authorized_targets: List[str],
                       objective: str) -> dict:
        """
        Phase 2: Attack Planning
        Uses DeepSeek-reasoner (mirrors ARXON's DeepSeek planning).
        Outputs structured plan verified by TLA+.
        """
        logger.info("=" * 60)
        logger.info("PHASE 2: ATTACK PLANNING")
        logger.info("=" * 60)

        # Get relevant knowledge
        rag_context = self.rag.get_relevant_context(
            json.dumps(recon_results.get("synthesis", ""))[:2000])

        # Get next ATT&CK techniques to cover
        next_techniques = self.tracker.get_next_techniques(10) if self.tracker else []

        planning_prompt = f"""You are a strategic ICS penetration testing planner.
Based on the reconnaissance results, create a detailed attack plan using MITRE ATT&CK for ICS.

RECONNAISSANCE RESULTS:
{json.dumps(recon_results.get('synthesis', recon_results), indent=2)[:4000]}

OBJECTIVE: {objective}

AUTHORIZED TARGETS (stay in scope): {', '.join(authorized_targets)}

ATT&CK TECHNIQUES TO PRIORITIZE:
{json.dumps(next_techniques, indent=2)[:2000]}

PAST ENGAGEMENT KNOWLEDGE:
{rag_context[:2000]}

Output a JSON object with:
{{
  "steps": [
    {{
      "step_id": "step_1",
      "phase": "recon|planning|exploitation|reporting",
      "target": "specific IP or host",
      "tool": "specific tool name from MCP server",
      "technique_id": "ATT&CK technique ID (e.g., T0812)",
      "description": "what this step does",
      "parameters": {{}},
      "risk_level": "low|medium|high|critical",
      "rollback": "how to undo if needed"
    }}
  ],
  "tactics": ["list of ATT&CK tactics covered"],
  "techniques": ["list of ATT&CK technique IDs"],
  "estimated_duration_minutes": 60,
  "risk_assessment": "overall risk summary"
}}

CRITICAL RULES:
1. NEVER target IPs outside the authorized list
2. Include rollback procedures for every exploitation step
3. Prioritize information gathering before active exploitation
4. Flag any steps that could cause operational disruption"""

        plan_output = self.llm.call_deepseek(
            planning_prompt,
            system="You are DeepSeek, acting as the strategic planner in an ARXON-style ICS penetration testing framework. Output valid JSON only.",
            model="deepseek-reasoner"
        )

        self._log("planning", "raw_plan", plan_output)

        # Parse plan
        try:
            clean = plan_output.strip()
            if "```json" in clean:
                clean = clean.split("```json")[1].split("```")[0]
            elif "```" in clean:
                clean = clean.split("```")[1].split("```")[0]
            plan = json.loads(clean)
        except (json.JSONDecodeError, TypeError):
            logger.error("Plan parsing failed, requesting simplified plan")
            plan = {"steps": [], "error": "Plan parsing failed"}

        return plan

    def phase_verify(self, plan: dict,
                     authorized_targets: List[str]) -> Tuple[bool, dict]:
        """
        Phase 2.5: TLA+ Verification Gate
        THIS IS THE KEY DIFFERENTIATOR FROM ORIGINAL ARXON.
        """
        logger.info("=" * 60)
        logger.info("PHASE 2.5: TLA+ SAFETY VERIFICATION")
        logger.info("=" * 60)

        allowed_tools = [
            "nmap_scan", "mqtt_enumerate", "coap_discover", "modbus_scan",
            "nuclei_scan", "firmware_analyze", "metasploit_run", "impacket_tool",
            "cve_lookup", "attack_technique_map"
        ]

        verification = verify_plan(plan, authorized_targets, allowed_tools)
        self._log("verification", "tla_result", verification)

        if verification["verified"]:
            logger.info("  PLAN VERIFIED: All safety properties satisfied")
        else:
            logger.warning(f"  PLAN REJECTED: {len(verification['violations'])} violations")
            for v in verification["violations"]:
                logger.warning(f"    - {v}")

        return verification["verified"], verification

    def phase_exploit(self, plan: dict, recon_context: str) -> dict:
        """
        Phase 3: Exploitation
        Two execution modes:
        1. Kimi Code CLI (preferred): K2.5 drives MCP tools natively for up to
           200-300 sequential tool calls with full autonomy
        2. API + Docker fallback: K2.5 generates code via API, executed in Docker

        Includes automatic rollback on failure using plan-defined rollback procedures.
        """
        logger.info("=" * 60)
        logger.info("PHASE 3: EXPLOITATION")
        logger.info("=" * 60)

        results = []
        exploit_steps = [s for s in plan.get("steps", [])
                         if s.get("phase") == "exploitation"]

        if not exploit_steps:
            logger.info("  No exploitation steps in plan")
            return {"results": []}

        # Mode 1: Try Kimi Code CLI first (native agentic execution)
        use_kimi_cli = self._check_kimi_cli_available()
        if use_kimi_cli:
            logger.info("  Using Kimi Code CLI for native agentic exploitation")
            cli_result = self._exploit_via_kimi_cli(exploit_steps, recon_context)
            if cli_result.get("status") == "success":
                results.append(cli_result)
                self._log("exploitation", "kimi_cli", cli_result)
                return {"results": results, "mode": "kimi_cli"}
            else:
                logger.warning("  Kimi CLI execution failed, falling back to API + Docker")

        # Mode 2: API-generated code + Docker execution
        logger.info("  Using K2.5 API + Docker isolated execution")

        # Decompose exploitation into parallel where possible
        exploit_task = f"Execute these exploitation steps safely:\n{json.dumps(exploit_steps, indent=2)}"
        subtasks = self.swarm.decompose(exploit_task, context=recon_context[:3000])

        # Execute by parallel group
        groups = {}
        for st in subtasks:
            g = st.get("parallel_group", 0)
            groups.setdefault(g, []).append(st)

        for group_id in sorted(groups.keys()):
            group = groups[group_id]
            logger.info(f"  Exploitation group {group_id} ({len(group)} tasks)")

            for subtask in group:
                # Find matching plan step for rollback procedure
                matching_step = next(
                    (s for s in exploit_steps if s.get("technique_id", "") in subtask.get("description", "")),
                    {}
                )
                rollback_cmd = matching_step.get("rollback", "")

                # Generate exploit code via K2.5
                exploit_prompt = f"""Generate a proof-of-concept for this ICS exploitation step.
The code must:
1. Be safe to run in an isolated Docker container
2. Include error handling and timeout
3. Log all actions for audit trail
4. NOT cause permanent damage to target systems
5. Print results as JSON to stdout

Step: {subtask['description']}
Context: {recon_context[:1500]}

Output executable Python code only. No explanations."""

                exploit_code = self.llm.call_kimi(exploit_prompt,
                    system="You are Kimi K2.5, the exploitation code generator in an ARXON-ICS framework.",
                    phase="exploitation")

                if exploit_code:
                    # Validate the code before execution
                    dangerous = ["rm -rf", "mkfs", "dd if=", "shutdown", "reboot",
                                 "fork()", "os.system('rm", "shutil.rmtree('/')",
                                 "import antigravity"]
                    code_safe = not any(d in (exploit_code or "") for d in dangerous)

                    if code_safe:
                        # Write code to file (avoids shell quoting issues)
                        import tempfile
                        with tempfile.NamedTemporaryFile(mode='w', suffix='.py',
                                                         dir=os.path.expanduser("~/arxon-ics/workspace"),
                                                         delete=False) as f:
                            f.write(exploit_code)
                            script_path = f.name

                        docker_result = run_in_executor(
                            f"python3 /data/{os.path.basename(script_path)}",
                            timeout=300,
                            rollback_command=rollback_cmd if rollback_cmd else None
                        )
                        result = {
                            "subtask_id": subtask["id"],
                            "code_preview": exploit_code[:1000],
                            "execution": docker_result,
                            "status": "executed",
                            "rollback_used": docker_result.get("rollback_executed", False)
                        }

                        try:
                            os.unlink(script_path)
                        except OSError:
                            pass
                    else:
                        result = {
                            "subtask_id": subtask["id"],
                            "code_preview": exploit_code[:300],
                            "status": "blocked_unsafe",
                            "reason": "Dangerous pattern detected in generated code"
                        }
                else:
                    result = {
                        "subtask_id": subtask["id"],
                        "status": "code_generation_failed"
                    }

                results.append(result)

                # Update ATT&CK tracker
                for step in exploit_steps:
                    if step.get("technique_id"):
                        self.tracker.record_attempt(
                            step["technique_id"],
                            tool=subtask.get("tool_hint", "custom"),
                            success=result.get("status") == "executed",
                            details=str(result.get("execution", {}).get("stdout", ""))[:500]
                        )

                self._log("exploitation", subtask["id"], result)

        return {"results": results, "mode": "api_docker"}

    def _check_kimi_cli_available(self) -> bool:
        """Check if Kimi Code CLI is installed and configured."""
        try:
            result = subprocess.run(["kimi", "--version"],
                                    capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _exploit_via_kimi_cli(self, exploit_steps: list,
                              recon_context: str) -> dict:
        """
        Run exploitation via Kimi Code CLI with native MCP tool access.
        K2.5 autonomously drives the MCP tools (nmap, modbus, mqtt, etc.)
        for up to 200-300 sequential tool calls without human intervention.
        """
        steps_description = "\n".join(
            f"- [{s.get('technique_id', 'N/A')}] {s.get('description', '')}"
            for s in exploit_steps
        )

        task = f"""You are conducting an authorized ICS penetration test.
Execute the following exploitation steps using the available MCP tools.
Log every action and result. Stop if any step causes unexpected system behavior.

AUTHORIZED STEPS:
{steps_description}

RECONNAISSANCE CONTEXT:
{recon_context[:2000]}

Execute each step sequentially. Report results as structured JSON."""

        output = self.llm.call_kimi_cli(task, cwd=os.path.expanduser("~/arxon-ics/workspace"))

        if output:
            return {"status": "success", "output": output[:5000], "mode": "kimi_cli"}
        return {"status": "failed", "output": "Kimi CLI returned no output"}

    def phase_report(self, recon: dict, plan: dict,
                     exploit_results: dict, objective: str) -> str:
        """
        Phase 4: Reporting + Learning
        Summarizes findings and stores in RAG for future engagements.
        """
        logger.info("=" * 60)
        logger.info("PHASE 4: REPORTING + LEARNING")
        logger.info("=" * 60)

        # Get coverage report
        coverage = self.tracker.get_coverage_report() if self.tracker else {}

        report_prompt = f"""Generate a comprehensive ICS penetration testing report.

OBJECTIVE: {objective}

RECONNAISSANCE SUMMARY:
{json.dumps(recon.get('synthesis', ''), indent=2)[:2000]}

ATTACK PLAN:
{json.dumps(plan, indent=2)[:2000]}

EXPLOITATION RESULTS:
{json.dumps(exploit_results, indent=2)[:2000]}

ATT&CK COVERAGE:
{json.dumps(coverage, indent=2)[:1000]}

Generate a structured report with:
1. Executive Summary
2. Scope and Methodology
3. Findings (Critical, High, Medium, Low)
4. ATT&CK for ICS Technique Coverage
5. Recommendations and Mitigations
6. Appendix: Raw Tool Outputs"""

        report = self.llm.call_deepseek(report_prompt, model="deepseek-chat")
        self._log("reporting", "final_report", report)

        # Store in RAG for future engagements
        summary_prompt = f"""Summarize the key findings, successful techniques,
and lessons learned from this ICS penetration test for future reference.
Be specific about what worked and what did not.

Results: {json.dumps(exploit_results, indent=2)[:3000]}"""

        summary = self.llm.call_deepseek(summary_prompt, model="deepseek-chat")
        if summary:
            self.rag.store_engagement(
                self.engagement_id, summary,
                {"coverage": coverage, "findings_count": len(exploit_results.get("results", []))},
                target=objective
            )
            logger.info("  Engagement stored in RAG knowledge base")

        return report

    # ================================================================
    # MAIN ENGAGEMENT RUNNER
    # ================================================================

    def run(self, targets: List[str], objective: str,
            scope_techniques: List[str] = None):
        """
        Run a complete ICS penetration testing engagement.
        This is the main entry point.
        """
        logger.info("=" * 60)
        logger.info(f"ARXON-ICS ENGAGEMENT: {self.engagement_id}")
        logger.info(f"Targets: {targets}")
        logger.info(f"Objective: {objective}")
        logger.info("=" * 60)

        start_time = time.time()

        # Initialize tracker
        self.tracker = ATTACKTracker(self.engagement_id, scope_techniques)

        # Phase 1: Reconnaissance
        recon = self.phase_recon(targets, objective)

        # Phase 2: Planning
        plan = self.phase_planning(recon, targets, objective)

        # Phase 2.5: TLA+ Verification
        verified, verification = self.phase_verify(plan, targets)
        if not verified:
            logger.error("ENGAGEMENT HALTED: Plan failed safety verification")
            logger.error(f"Violations: {verification['violations']}")

            # Ask DeepSeek-reasoner to fix the plan
            fix_prompt = f"""The attack plan failed safety verification.
Violations: {json.dumps(verification['violations'])}
Original plan: {json.dumps(plan, indent=2)[:3000]}
Authorized targets: {targets}

Fix the plan to resolve all violations. Output corrected JSON plan."""

            fixed_plan = self.llm.call_deepseek(fix_prompt, model="deepseek-reasoner")
            if fixed_plan:
                try:
                    clean = fixed_plan.strip()
                    if "```json" in clean:
                        clean = clean.split("```json")[1].split("```")[0]
                    plan = json.loads(clean)
                    verified, verification = self.phase_verify(plan, targets)
                except:
                    pass

            if not verified:
                logger.error("ENGAGEMENT ABORTED: Could not produce safe plan")
                self._log("abort", "verification_failed", verification)
                return

        # Phase 3: Exploitation
        recon_context = json.dumps(recon.get("synthesis", ""))[:3000]
        exploit_results = self.phase_exploit(plan, recon_context)

        # Phase 4: Report + Learn
        report = self.phase_report(recon, plan, exploit_results, objective)

        elapsed = round(time.time() - start_time, 1)
        logger.info(f"ENGAGEMENT COMPLETE in {elapsed}s")
        logger.info(f"Log: {self.log_path}")

        # Final coverage report
        coverage = self.tracker.get_coverage_report()
        logger.info(f"ATT&CK Coverage: {coverage['coverage_percentage']}%")

        # Cost summary
        cost_summary = self.cost_tracker.get_summary()
        logger.info(f"Total cost: ${cost_summary['total_estimated_cost_usd']:.4f}")
        logger.info(f"Total tokens: {cost_summary['total_tokens']:,}")
        for model, stats in cost_summary.get("by_model", {}).items():
            logger.info(f"  {model}: {stats['calls']} calls, {stats['tokens']:,} tokens, ${stats['cost']:.4f}")
        self._log("cost", "summary", cost_summary)

        return {
            "engagement_id": self.engagement_id,
            "duration_seconds": elapsed,
            "report": report,
            "coverage": coverage,
            "cost": cost_summary,
            "log_path": self.log_path
        }


# ================================================================
# CLI ENTRY POINT
# ================================================================

def main():
    import argparse

    parser = argparse.ArgumentParser(description="ARXON-ICS Penetration Testing Framework")
    parser.add_argument("targets", nargs="+", help="Target IPs or ranges")
    parser.add_argument("-o", "--objective", required=True, help="Engagement objective")
    parser.add_argument("-e", "--engagement-id", default=None, help="Custom engagement ID")
    parser.add_argument("-t", "--techniques", nargs="*", default=None,
                        help="ATT&CK technique IDs to focus on")
    parser.add_argument("--ingest-knowledge", action="store_true",
                        help="Ingest knowledge base before starting")

    args = parser.parse_args()

    if args.ingest_knowledge:
        kb = KnowledgeBase()
        kb.ingest_knowledge_dir()

    orch = ARXONOrchestrator(engagement_id=args.engagement_id)
    result = orch.run(args.targets, args.objective, args.techniques)

    if result:
        print("\n" + "=" * 60)
        print("ENGAGEMENT SUMMARY")
        print("=" * 60)
        print(f"ID: {result['engagement_id']}")
        print(f"Duration: {result['duration_seconds']}s")
        print(f"Coverage: {result['coverage']['coverage_percentage']}%")
        cost = result.get('cost', {})
        print(f"Total Cost: ${cost.get('total_estimated_cost_usd', 0):.4f}")
        print(f"Total Tokens: {cost.get('total_tokens', 0):,}")
        print(f"API Calls: {cost.get('total_calls', 0)}")
        print(f"\nCost by model:")
        for model, stats in cost.get('by_model', {}).items():
            print(f"  {model}: {stats['calls']} calls, ${stats['cost']:.4f}")
        print(f"\nCost by phase:")
        for phase, stats in cost.get('by_phase', {}).items():
            print(f"  {phase}: {stats['calls']} calls, ${stats['cost']:.4f}")
        print(f"\nLog: {result['log_path']}")
        print(f"Cost log: ~/arxon-ics/logs/cost_tracking.jsonl")


if __name__ == "__main__":
    main()
