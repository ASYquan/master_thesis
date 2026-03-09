#!/usr/bin/env python3
"""
Token and cost tracking for multi-model orchestration.
Wraps every LLM call to record input/output tokens, model used,
phase, and estimated cost. Essential for answering the thesis question:
"Is multi-model routing actually cheaper than single-model?"
"""
import json
import os
import time
from datetime import datetime
from typing import Optional

COST_LOG = os.path.expanduser("~/arxon-ics/logs/cost_tracking.jsonl")

# Approximate pricing per 1M tokens (as of March 2026)
MODEL_PRICING = {
    "deepseek-chat":        {"input": 0.14,  "output": 0.28},
    "deepseek-reasoner":    {"input": 0.55,  "output": 2.19},
    "kimi-k2.5":            {"input": 0.60,  "output": 3.00},
    "moonshotai/kimi-k2.5": {"input": 0.60,  "output": 3.00},  # via OpenRouter
    "anthropic/claude-sonnet-4": {"input": 3.00, "output": 15.00},
    "google/gemini-2.5-flash:free": {"input": 0.0, "output": 0.0},
    "qwen2.5-coder:latest": {"input": 0.0,  "output": 0.0},   # local Ollama
    "deepseek-r1:8b":       {"input": 0.0,  "output": 0.0},   # local Ollama
}


class CostTracker:
    def __init__(self, engagement_id: str):
        self.engagement_id = engagement_id
        self.records = []

    def record(self, model: str, phase: str, input_tokens: int,
               output_tokens: int, latency_ms: int, success: bool = True):
        """Record a single LLM call."""
        pricing = MODEL_PRICING.get(model, {"input": 1.0, "output": 3.0})
        cost = (input_tokens * pricing["input"] + output_tokens * pricing["output"]) / 1_000_000

        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "engagement_id": self.engagement_id,
            "model": model,
            "phase": phase,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens,
            "estimated_cost_usd": round(cost, 6),
            "latency_ms": latency_ms,
            "success": success
        }
        self.records.append(entry)

        # Append to log file
        os.makedirs(os.path.dirname(COST_LOG), exist_ok=True)
        with open(COST_LOG, 'a') as f:
            f.write(json.dumps(entry) + "\n")

    def estimate_tokens(self, text: str) -> int:
        """Rough token estimate (4 chars per token heuristic).
        For precise counting, use tiktoken with the appropriate encoding."""
        try:
            import tiktoken
            enc = tiktoken.get_encoding("cl100k_base")
            return len(enc.encode(text))
        except ImportError:
            return len(text) // 4

    def get_summary(self) -> dict:
        """Generate cost summary grouped by model and phase."""
        by_model = {}
        by_phase = {}
        total_cost = 0.0
        total_tokens = 0

        for r in self.records:
            model = r["model"]
            phase = r["phase"]

            by_model.setdefault(model, {"calls": 0, "tokens": 0, "cost": 0.0})
            by_model[model]["calls"] += 1
            by_model[model]["tokens"] += r["total_tokens"]
            by_model[model]["cost"] += r["estimated_cost_usd"]

            by_phase.setdefault(phase, {"calls": 0, "tokens": 0, "cost": 0.0})
            by_phase[phase]["calls"] += 1
            by_phase[phase]["tokens"] += r["total_tokens"]
            by_phase[phase]["cost"] += r["estimated_cost_usd"]

            total_cost += r["estimated_cost_usd"]
            total_tokens += r["total_tokens"]

        return {
            "engagement_id": self.engagement_id,
            "total_calls": len(self.records),
            "total_tokens": total_tokens,
            "total_estimated_cost_usd": round(total_cost, 4),
            "by_model": by_model,
            "by_phase": by_phase
        }
