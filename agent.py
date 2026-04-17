#!/usr/bin/env python3
"""
agent.py — LangGraph-style ReAct hunting agent for bug bounty automation.

Architecture
────────────
Primary:  Real LangGraph + langchain-ollama  (pip install langgraph langchain-ollama)
Fallback: Built-in ReAct loop using Ollama native tool calling  (works out of the box)

Both paths expose identical tools and persistent memory — the difference is
that the real LangGraph backend handles interrupts, checkpoints, and parallel
subgraphs correctly.

ReAct loop:
    Observe (state) → Think (LLM) → Act (tool) → Observe (result) → loop
    ↳ LLM picks next tool based on ALL prior findings, not a priority table
    ↳ Working memory is compressed every 5 steps to stay within context window
    ↳ Full finding history persists to JSON session — survives crashes/restarts

Memory layers
─────────────
  working_memory  : LLM-maintained running notes (updated after each step)
  findings_log    : [{tool, severity, summary, timestamp}, ...]
  observation_buf : last 5 raw tool outputs (sliding window, avoids bloat)
  session_file    : everything above persisted to disk (JSON)

Usage
─────
  python3 agent.py --target example.com
  python3 agent.py --target example.com --cookie "JSESSIONID=abc" --time 4
  python3 agent.py --target example.com --scope-lock --no-brain
  python3 agent.py --target example.com --langgraph          # force LangGraph
  python3 agent.py --target example.com --resume SESSION_ID

From tools/hunt.py:
  tools/hunt.py --target x --agent              # drops into agent mode
  tools/hunt.py --target x --agent --langgraph  # with real LangGraph
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any

from memory.hunt_journal import HuntJournal
from memory.target_profile import default_memory_dir, load_target_profile

# ── LangGraph optional import ──────────────────────────────────────────────────
try:
    from langgraph.graph import StateGraph, END
    from langgraph.graph.message import add_messages
    from langgraph.prebuilt import ToolNode, tools_condition
    from langchain_core.messages import HumanMessage, SystemMessage, AIMessage, ToolMessage
    from langchain_core.tools import tool as lc_tool
    try:
        from langchain_ollama import ChatOllama
        _LANGGRAPH_OK = True
    except ImportError:
        from langchain_community.chat_models import ChatOllama
        _LANGGRAPH_OK = True
except ImportError:
    _LANGGRAPH_OK = False
    StateGraph = END = None
    add_messages = None

# ── Ollama native tool calling (fallback / always available) ───────────────────
try:
    import ollama as _ollama_lib
    _OLLAMA_OK = True
except ImportError:
    _ollama_lib = None
    _OLLAMA_OK = False

# ── tools/hunt.py compatibility loader (avoids running main()) ─────────────────
_hunt = None


class _HuntCompat:
    """Bridge the newer autonomous agent onto this repo's current hunt module."""

    _SYNC_ATTRS = {
        "BASE_DIR",
        "TOOLS_DIR",
        "TARGETS_DIR",
        "RECON_DIR",
        "FINDINGS_DIR",
        "REPORTS_DIR",
    }

    _OPTIONAL_TOOL_FUNCS = {
        "check_tools": "check_tools",
        "run_js_analysis": "run_js_analysis",
        "run_secret_hunt": "run_secret_hunt",
        "run_repo_source_hunt": "run_repo_source_hunt",
        "run_param_discovery": "run_param_discovery",
        "run_post_param_discovery": "run_post_param_discovery",
        "run_api_fuzz": "run_api_fuzz",
        "run_cors_check": "run_cors_check",
        "run_cms_exploit": "run_cms_exploit",
        "run_rce_scan": "run_rce_scan",
        "run_sqlmap_targeted": "run_sqlmap_targeted",
        "run_sqlmap_on_file": "run_sqlmap_request_file",
        "run_jwt_audit": "run_jwt_audit",
        "run_cve_hunt": "run_cve_hunt",
        "run_zero_day_fuzzer": "run_zero_day_fuzzer",
        "generate_reports": "generate_reports",
    }

    def __init__(self, module):
        self._module = module
        self.BASE_DIR = module.BASE_DIR
        self.TOOLS_DIR = module.TOOLS_DIR
        self.TARGETS_DIR = module.TARGETS_DIR
        self.RECON_DIR = module.RECON_DIR
        self.FINDINGS_DIR = module.FINDINGS_DIR
        self.REPORTS_DIR = module.REPORTS_DIR

    def __setattr__(self, name: str, value: Any) -> None:
        object.__setattr__(self, name, value)
        module = getattr(self, "_module", None)
        if module is not None and name in self._SYNC_ATTRS:
            setattr(module, name, value)

    def __getattr__(self, name: str):
        return getattr(self._module, name)

    def supported_tool_names(self) -> set[str]:
        supported = {"run_recon", "run_vuln_scan"}
        for tool_name, func_name in self._OPTIONAL_TOOL_FUNCS.items():
            if hasattr(self._module, func_name):
                supported.add(tool_name)
        return supported

    def _resolve_recon_dir(self, domain: str) -> str:
        return os.path.join(self.RECON_DIR, domain)

    def _resolve_findings_dir(self, domain: str, create: bool = False) -> str:
        path = os.path.join(self.FINDINGS_DIR, domain)
        if create:
            os.makedirs(path, exist_ok=True)
        return path

    def _activate_recon_session(
        self,
        domain: str,
        *,
        requested_session_id: str = "latest",
        create: bool = True,
    ) -> tuple[str, str]:
        """Create a lightweight session directory for agent traces and resumes."""
        session_root = os.path.join(self.TARGETS_DIR, domain, "sessions")
        if create:
            os.makedirs(session_root, exist_ok=True)

        session_id = requested_session_id
        if requested_session_id == "latest":
            existing = [
                name for name in os.listdir(session_root)
                if os.path.isdir(os.path.join(session_root, name))
            ] if os.path.isdir(session_root) else []
            session_id = sorted(existing)[-1] if existing else datetime.now().strftime("%Y%m%d-%H%M%S")

        session_dir = os.path.join(session_root, session_id)
        recon_dir = os.path.join(session_dir, "recon")
        if create:
            os.makedirs(recon_dir, exist_ok=True)
        return session_id, recon_dir

    def run_recon(
        self,
        domain: str,
        *,
        scope_lock: bool = False,
        max_urls: int = 100,
        quick: bool = False,
    ) -> bool:
        # Current orchestrator only supports quick/full split.
        _ = (scope_lock, max_urls)
        return self._module.run_recon(domain, quick=quick)

    def run_vuln_scan(self, domain: str, *, quick: bool = False, full: bool = False) -> bool:
        return self._module.run_vuln_scan(domain, quick=False if full else quick)


def _h():
    """Lazy-load the current tools/hunt.py module once."""
    global _hunt
    if _hunt is None:
        import importlib.util

        _here = os.path.dirname(os.path.abspath(__file__))
        hunt_path = os.path.join(_here, "tools", "hunt.py")
        spec = importlib.util.spec_from_file_location("hunt_tools", hunt_path)
        module = importlib.util.module_from_spec(spec)
        sys.modules.setdefault("hunt_tools", module)
        spec.loader.exec_module(module)
        _hunt = _HuntCompat(module)
    return _hunt


def _load_agent_runtime_config() -> dict[str, Any]:
    """Load optional repo config via tools/hunt.py when available."""
    try:
        config = _h().load_config()
        return config if isinstance(config, dict) else {}
    except Exception:
        return {}


def _resolve_ctf_mode(explicit: bool | None = None) -> bool:
    """Resolve CTF mode from explicit override or repo config."""
    if explicit is not None:
        return explicit
    return bool(_load_agent_runtime_config().get("ctf_mode", False))


def _normalize_autopilot_mode(mode: str | None) -> str:
    """Normalize autopilot checkpoint mode with a safe default."""
    normalized = str(mode or "").strip().lower()
    return normalized if normalized in {"paranoid", "normal", "yolo"} else "paranoid"


def _finish_floor_for_mode(mode: str) -> int:
    """Set a conservative minimum number of tool runs before finish."""
    normalized = _normalize_autopilot_mode(mode)
    return {
        "paranoid": 8,
        "normal": 6,
        "yolo": 4,
    }[normalized]

# ── brain.py import ───────────────────────────────────────────────────────────
try:
    _here = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, _here)
    from brain import Brain, BRAIN_SYSTEM, MODEL_PRIORITY, OLLAMA_HOST, _pick_model
    _BRAIN_OK = True
except Exception as _brain_err:
    _BRAIN_OK = False
    BRAIN_SYSTEM = ""
    MODEL_PRIORITY = ["qwen3:8b"]
    OLLAMA_HOST = "http://localhost:11434"

# ── Colours ───────────────────────────────────────────────────────────────────
GREEN   = "\033[0;32m"
CYAN    = "\033[0;36m"
YELLOW  = "\033[1;33m"
RED     = "\033[0;31m"
MAGENTA = "\033[0;35m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
NC      = "\033[0m"

MAX_OBS_CHARS    = 3000    # truncate tool output kept in observation buffer
MAX_CTX_CHARS    = 18000   # max chars sent to LLM per step
MAX_FINDINGS_LOG = 200     # cap stored findings
MEMORY_REFRESH_N = 5       # compress working_memory every N steps


# ──────────────────────────────────────────────────────────────────────────────
#  Tool definitions  (JSON Schema — compatible with Ollama native tool calling)
# ──────────────────────────────────────────────────────────────────────────────

_ALL_TOOL_SPECS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "run_recon",
            "description": (
                "Run full subdomain enumeration + live host discovery on the target domain. "
                "This MUST be the first step if recon data does not exist. "
                "Returns: number of live hosts found, key tech stacks detected."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "scope_lock": {
                        "type": "boolean",
                        "description": "If true, skip subdomain enum and only probe the exact target given.",
                        "default": False,
                    },
                    "max_urls": {
                        "type": "integer",
                        "description": "Max URLs to collect (default 100, use 200+ for thorough recon).",
                        "default": 100,
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_tools",
            "description": (
                "Check which external security tools are installed locally. "
                "Use when scans fail unexpectedly or you need to understand environment limits "
                "before choosing a tool-heavy next step."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_vuln_scan",
            "description": (
                "Run the core vulnerability scanner (nuclei templates + custom checks). "
                "Tests for CVEs, misconfigs, exposed panels, default creds, takeover candidates. "
                "Returns: finding count by severity."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "quick": {
                        "type": "boolean",
                        "description": "If true, run fast subset of templates only.",
                        "default": False,
                    },
                    "full": {
                        "type": "boolean",
                        "description": "If true, run all templates including slow ones.",
                        "default": False,
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_js_analysis",
            "description": (
                "Download and analyse all JavaScript files found during recon. "
                "Extracts: API keys, secrets, hardcoded tokens, internal endpoints, "
                "GraphQL schemas, and auth-bypass hints. Use when JS files were discovered."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_secret_hunt",
            "description": (
                "Scan for leaked secrets: TruffleHog on JS/git repos, GitHound on GitHub, "
                "hardcoded AWS/GCP/Azure keys, API tokens, private keys. "
                "Always worth running — secrets bypass all other controls."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_repo_source_hunt",
            "description": (
                "Scan a GitHub public repo or local repo path for leaked secrets, risky configs, "
                "and GitHub Actions / CI issues."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "repo_url": {
                        "type": "string",
                        "description": "GitHub public repo URL or owner/repo reference",
                        "default": "",
                    },
                    "repo_path": {
                        "type": "string",
                        "description": "Local repository path already present on disk",
                        "default": "",
                    },
                    "allow_large_repo": {
                        "type": "boolean",
                        "description": "Allow clone even when source-hunt thresholds are exceeded",
                        "default": False,
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_param_discovery",
            "description": (
                "Brute-force GET URL parameters using arjun + paramspider on all live hosts. "
                "Use when parameterized URLs are sparse or the site returns data conditionally. "
                "Returns: new parameterized URLs added to the attack surface."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_post_param_discovery",
            "description": (
                "Discover POST form endpoints and their parameter names using lightpanda "
                "(JS-rendered HTML) + arjun POST brute-force. "
                "Mandatory for JSP/Java/Spring apps, ASP.NET WebForms, any app with login forms. "
                "Then runs sqlmap on discovered POST endpoints automatically. "
                "Pass cookies if the forms are behind authentication."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "cookies": {
                        "type": "string",
                        "description": "Session cookie string e.g. 'JSESSIONID=abc; token=xyz'",
                        "default": "",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_api_fuzz",
            "description": (
                "Fuzz API endpoints for IDOR, auth bypass, privilege escalation, "
                "and unauthenticated access. Tests REST + GraphQL + gRPC. "
                "Use when API endpoints or numeric IDs were found in recon."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_cors_check",
            "description": (
                "Test all live hosts for CORS misconfigurations: null origin, "
                "wildcard with credentials, trusted subdomain bypass. "
                "High-priority when authenticated API endpoints are present."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_cms_exploit",
            "description": (
                "Run CMS-specific exploit checks: Drupalgeddon (CVE-2014-3704, CVE-2018-7600), "
                "WordPress plugin vulns + user enum, Joomla RCE, Magento SQLi. "
                "Use immediately when a CMS is detected — especially Drupal < 8 or WordPress."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_rce_scan",
            "description": (
                "Scan for Remote Code Execution vectors: Log4Shell (JNDI), Tomcat PUT upload, "
                "JBoss admin consoles, SSTI (Jinja2/Twig/Freemarker), shellshock, "
                "interactsh OOB callbacks. Use when Java/Tomcat/JBoss/Struts is detected."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_sqlmap_targeted",
            "description": (
                "Run sqlmap against parameterized GET URLs found in recon. "
                "Tests error-based, boolean-blind, time-blind, UNION injection. "
                "Use when parameterized URLs exist OR nuclei flagged SQL-related findings."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_sqlmap_on_file",
            "description": (
                "Run sqlmap against a specific raw HTTP request file (Burp-style). "
                "Use when you know a specific endpoint with POST params that needs SQLi testing. "
                "Provide the full path to the saved request file."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "request_file": {
                        "type": "string",
                        "description": "Absolute path to raw HTTP request file.",
                    },
                    "level": {
                        "type": "integer",
                        "description": "sqlmap level 1-5 (default 5).",
                        "default": 5,
                    },
                    "risk": {
                        "type": "integer",
                        "description": "sqlmap risk 1-3 (default 3).",
                        "default": 3,
                    },
                },
                "required": ["request_file"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_jwt_audit",
            "description": (
                "Audit JWT tokens found in recon artifacts: algorithm confusion (alg=none, "
                "RS256→HS256), weak HMAC secret cracking, forged claims. "
                "Use when JWT tokens appear in URLs, cookies, or response headers."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_cve_hunt",
            "description": (
                "Run the CVE hunter against detected technologies and live targets. "
                "Correlates recon tech fingerprints with known CVEs and nuclei CVE templates. "
                "Use when tech stack has been identified and you want fast known-vuln coverage."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_zero_day_fuzzer",
            "description": (
                "Run the zero-day/logic fuzzer against the target to probe unusual methods, "
                "header handling, parameter edge cases, and business-logic style flaws. "
                "Use after recon when standard scans have not exhausted the attack surface."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "deep": {
                        "type": "boolean",
                        "description": "If true, use deeper and slower fuzzing routines.",
                        "default": False,
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "generate_reports",
            "description": (
                "Generate markdown reports from current findings artifacts for this target. "
                "Use near the end after meaningful findings or scans have completed."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_autopilot_state",
            "description": (
                "Load the combined autopilot bootstrap view for this target: cached recon status, "
                "memory summary, recommended first targets, guard cooldowns, and the next action. "
                "Use this before active testing to resume quickly with minimal context."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "repo_root": {
                        "type": "string",
                        "description": "Optional repository root override (defaults to current checkout).",
                        "default": "",
                    },
                    "memory_dir": {
                        "type": "string",
                        "description": "Optional hunt-memory directory override.",
                        "default": "",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_guard_status",
            "description": (
                "Read the persisted request guard state for this target: tracked hosts, failure counts, "
                "and active cooldowns. Use this when active testing slows down or you need to avoid tripped hosts."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "memory_dir": {
                        "type": "string",
                        "description": "Optional hunt-memory directory override.",
                        "default": "",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_repo_source_summary",
            "description": (
                "Read previously generated repository source-hunt artifacts for this target: "
                "repo metadata, secret findings count, CI findings count, and the saved markdown summary."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_resume_summary",
            "description": (
                "Read hunt-memory history for this target and summarize prior sessions, "
                "untested endpoints, and cross-target pattern matches before resuming work."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "memory_dir": {
                        "type": "string",
                        "description": "Optional hunt-memory directory override.",
                        "default": "",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_surface_summary",
            "description": (
                "Rank cached recon output with hunt-memory context and return a prioritized "
                "attack surface summary. Use after recon to decide where to hunt first."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "repo_root": {
                        "type": "string",
                        "description": "Optional repository root override (defaults to current checkout).",
                        "default": "",
                    },
                    "memory_dir": {
                        "type": "string",
                        "description": "Optional hunt-memory directory override.",
                        "default": "",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_intel",
            "description": (
                "Fetch memory-aware CVE and disclosure intel for the target. "
                "Automatically falls back to recon-detected tech stack when no tech list is provided."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "tech": {
                        "type": "string",
                        "description": "Optional comma-separated tech stack override.",
                        "default": "",
                    },
                    "program": {
                        "type": "string",
                        "description": "Optional HackerOne program handle for disclosed-report lookups.",
                        "default": "",
                    },
                    "memory_dir": {
                        "type": "string",
                        "description": "Optional hunt-memory directory override.",
                        "default": "",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "remember_finding",
            "description": (
                "Persist a confirmed/partial/rejected finding into hunt memory so future hunts "
                "can reuse the endpoint, technique, and tech stack context."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Optional target override; defaults to the current domain.",
                        "default": "",
                    },
                    "vuln_class": {
                        "type": "string",
                        "description": "Vulnerability class, e.g. idor or ssrf.",
                    },
                    "endpoint": {
                        "type": "string",
                        "description": "Affected URL or normalized path.",
                    },
                    "result": {
                        "type": "string",
                        "description": "Remember outcome: confirmed, rejected, partial, or informational.",
                    },
                    "severity": {
                        "type": "string",
                        "description": "Optional severity label.",
                        "default": "",
                    },
                    "payout": {
                        "type": "number",
                        "description": "Optional payout amount.",
                    },
                    "technique": {
                        "type": "string",
                        "description": "Optional technique label.",
                        "default": "",
                    },
                    "notes": {
                        "type": "string",
                        "description": "Optional notes describing the finding.",
                        "default": "",
                    },
                    "tags": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional list of tags.",
                        "default": [],
                    },
                    "tech_stack": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional list of technologies for pattern learning.",
                        "default": [],
                    },
                    "memory_dir": {
                        "type": "string",
                        "description": "Optional hunt-memory directory override.",
                        "default": "",
                    },
                },
                "required": ["vuln_class", "endpoint", "result"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_recon_summary",
            "description": (
                "Read and summarize current recon data: live hosts, tech stack, "
                "discovered paths, parameterized URLs, CMS detections. "
                "Use to refresh your understanding before deciding next action."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_findings_summary",
            "description": (
                "Read and summarize all vulnerability findings discovered so far. "
                "Returns severity breakdown, top findings, and suggested exploit chains. "
                "Use before deciding to run additional tools or write the final report."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "update_working_memory",
            "description": (
                "Update your working notes about this target. Call this after making "
                "a significant discovery or after each tool run to keep your notes current. "
                "These notes persist across all steps and are always visible to you."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "notes": {
                        "type": "string",
                        "description": "Your updated notes about the target, findings, and next priorities.",
                    }
                },
                "required": ["notes"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "finish",
            "description": (
                "Signal that the hunt is complete. Call this when: all high-priority tools "
                "have run, time budget is close to exhausted, or no further tools would "
                "add new findings. Provide a brief verdict."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "verdict": {
                        "type": "string",
                        "description": "Brief summary: what was found, what's worth reporting.",
                    }
                },
                "required": ["verdict"],
            },
        },
    },
]

_DISPATCHER_ONLY_TOOLS = {
    "read_autopilot_state",
    "read_guard_status",
    "read_repo_source_summary",
    "read_resume_summary",
    "read_surface_summary",
    "run_intel",
    "remember_finding",
    "read_recon_summary",
    "read_findings_summary",
    "update_working_memory",
    "finish",
}


def _enabled_tool_specs() -> list[dict]:
    """Expose only tools that are wired into the current checkout."""
    available = _h().supported_tool_names() | _DISPATCHER_ONLY_TOOLS
    return [spec for spec in _ALL_TOOL_SPECS if spec["function"]["name"] in available]


TOOLS = _enabled_tool_specs()
TOOL_NAMES = {t["function"]["name"] for t in TOOLS}


def _phase_flags(completed_steps: list[str]) -> dict[str, bool]:
    completed = set(completed_steps)
    return {
        "recon": "run_recon" in completed,
        "scan": "run_vuln_scan" in completed,
        "tool_check": "check_tools" in completed,
        "js_analysis": "run_js_analysis" in completed,
        "secret_hunt": "run_secret_hunt" in completed,
        "param_discovery": "run_param_discovery" in completed,
        "post_param_discovery": "run_post_param_discovery" in completed,
        "api_fuzz": "run_api_fuzz" in completed,
        "cors": "run_cors_check" in completed,
        "cms_exploit": "run_cms_exploit" in completed,
        "rce_scan": "run_rce_scan" in completed,
        "sqlmap": "run_sqlmap_targeted" in completed or "run_sqlmap_on_file" in completed,
        "jwt_audit": "run_jwt_audit" in completed,
        "cve_hunt": "run_cve_hunt" in completed,
        "zero_day_fuzzer": "run_zero_day_fuzzer" in completed,
        "reports_generated": "generate_reports" in completed,
    }


# ──────────────────────────────────────────────────────────────────────────────
#  Memory
# ──────────────────────────────────────────────────────────────────────────────

class HuntMemory:
    """
    Three-layer memory:
      1. working_memory   — LLM's rolling notes (updated by update_working_memory tool)
      2. findings_log     — structured list of all discoveries [{tool, severity, text, ts}]
      3. observation_buf  — last N raw tool outputs, used to build LLM context
    All layers are persisted to a JSON session file.
    """

    def __init__(self, session_file: str):
        self.session_file    = session_file
        self.working_memory  = ""
        self.bootstrap_context = ""
        self.findings_log:   list[dict] = []
        self.observation_buf: list[dict] = []   # {tool, ts, text}
        self.completed_steps: list[str]  = []
        self.step_count      = 0
        self._load()

    def _load(self) -> None:
        if os.path.isfile(self.session_file):
            try:
                data = json.loads(Path(self.session_file).read_text())
                self.working_memory   = data.get("working_memory", "")
                self.findings_log     = data.get("findings_log", [])
                self.observation_buf  = data.get("observation_buf", [])[-10:]
                self.completed_steps  = data.get("completed_steps", [])
                self.step_count       = data.get("step_count", 0)
            except Exception:
                pass

    def save(self) -> None:
        Path(self.session_file).parent.mkdir(parents=True, exist_ok=True)
        data = {
            "working_memory":  self.working_memory,
            "findings_log":    self.findings_log[-MAX_FINDINGS_LOG:],
            "observation_buf": self.observation_buf[-10:],
            "completed_steps": self.completed_steps,
            "step_count":      self.step_count,
            "saved_at":        datetime.now().isoformat(),
        }
        Path(self.session_file).write_text(json.dumps(data, indent=2))

    def add_observation(self, tool: str, text: str) -> None:
        """Record a tool output to the sliding observation window."""
        entry = {
            "tool": tool,
            "ts":   datetime.now().isoformat(),
            "text": text[:MAX_OBS_CHARS],
        }
        self.observation_buf.append(entry)
        if len(self.observation_buf) > 15:
            self.observation_buf = self.observation_buf[-10:]

    def add_finding(self, tool: str, severity: str, text: str) -> None:
        self.findings_log.append({
            "tool":     tool,
            "severity": severity,
            "text":     text[:500],
            "ts":       datetime.now().isoformat(),
        })

    def findings_summary(self) -> str:
        """Compact summary of all findings for LLM context."""
        if not self.findings_log:
            return "No findings yet."
        by_sev: dict[str, list[str]] = {}
        for f in self.findings_log[-50:]:
            by_sev.setdefault(f["severity"].upper(), []).append(f"{f['tool']}: {f['text'][:120]}")
        lines = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if sev in by_sev:
                lines.append(f"[{sev}] ({len(by_sev[sev])} items)")
                lines.extend(f"  • {x}" for x in by_sev[sev][:5])
        return "\n".join(lines) or "No classified findings."

    def recent_observations(self, n: int = 3) -> str:
        """Last n tool outputs formatted for LLM context."""
        recents = self.observation_buf[-n:]
        if not recents:
            return "No tool outputs yet."
        parts = []
        for obs in recents:
            parts.append(f"[{obs['tool']}]\n{obs['text']}")
        return "\n\n".join(parts)


# ──────────────────────────────────────────────────────────────────────────────
#  Tool dispatcher  (maps tool names → hunt.py functions)
# ──────────────────────────────────────────────────────────────────────────────

class ToolDispatcher:
    """Execute tool calls and return plain-text observations."""

    def __init__(self, domain: str, memory: HuntMemory,
                 scope_lock: bool = False, max_urls: int = 100,
                 default_cookies: str = ""):
        self.domain          = domain
        self.memory          = memory
        self.scope_lock      = scope_lock
        self.max_urls        = max_urls
        self.default_cookies = default_cookies

    def _resolve_memory_dir(self, override: str = "") -> str:
        resolved = str(override or "").strip()
        if resolved:
            return resolved
        return str(default_memory_dir(_h().BASE_DIR))

    def dispatch(self, name: str, args: dict) -> str:
        """Execute named tool and return text observation."""
        h = _h()
        domain = self.domain
        t0 = time.time()

        try:
            if name == "run_recon":
                ok = h.run_recon(
                    domain,
                    scope_lock=args.get("scope_lock", self.scope_lock),
                    max_urls=int(args.get("max_urls", self.max_urls)),
                )
                obs = self._summarize_recon(domain, ok)

            elif name == "check_tools":
                installed, missing = h.check_tools()
                obs = self._summarize_tools(installed, missing)

            elif name == "run_vuln_scan":
                ok = h.run_vuln_scan(
                    domain,
                    quick=bool(args.get("quick", False)),
                    full=bool(args.get("full", False)),
                )
                obs = self._summarize_findings(domain, "scan", ok)

            elif name == "run_js_analysis":
                ok = h.run_js_analysis(domain)
                obs = self._summarize_findings(domain, "js", ok)

            elif name == "run_secret_hunt":
                ok = h.run_secret_hunt(domain)
                obs = self._summarize_findings(domain, "secrets", ok)

            elif name == "run_repo_source_hunt":
                ok = h.run_repo_source_hunt(
                    domain,
                    repo_url=str(args.get("repo_url", "")),
                    repo_path=str(args.get("repo_path", "")),
                    allow_large_repo=bool(args.get("allow_large_repo", False)),
                )
                obs = self._summarize_repo_source(domain, ok)

            elif name == "run_param_discovery":
                ok = h.run_param_discovery(domain)
                obs = self._summarize_params(domain, ok)

            elif name == "run_post_param_discovery":
                cookies = args.get("cookies", self.default_cookies)
                ok = h.run_post_param_discovery(domain, cookies=cookies)
                obs = self._summarize_post_params(domain, ok)

            elif name == "run_api_fuzz":
                ok = h.run_api_fuzz(domain)
                obs = self._summarize_findings(domain, "api", ok)

            elif name == "run_cors_check":
                ok = h.run_cors_check(domain)
                obs = self._summarize_findings(domain, "cors", ok)

            elif name == "run_cms_exploit":
                ok = h.run_cms_exploit(domain)
                obs = self._summarize_findings(domain, "cms", ok)

            elif name == "run_rce_scan":
                ok = h.run_rce_scan(domain)
                obs = self._summarize_findings(domain, "rce", ok)

            elif name == "run_sqlmap_targeted":
                ok = h.run_sqlmap_targeted(domain)
                obs = self._summarize_findings(domain, "sqlmap", ok)

            elif name == "run_sqlmap_on_file":
                req_file = args.get("request_file", "")
                if not req_file or not os.path.isfile(req_file):
                    return f"ERROR: request_file not found: {req_file}"
                ok = h.run_sqlmap_request_file(
                    req_file, domain=domain,
                    level=int(args.get("level", 5)),
                    risk=int(args.get("risk", 3)),
                )
                obs = f"sqlmap (request-file) completed. Injectable: {ok}"

            elif name == "run_jwt_audit":
                ok = h.run_jwt_audit(domain)
                obs = self._summarize_findings(domain, "jwt", ok)

            elif name == "run_cve_hunt":
                ok = h.run_cve_hunt(domain)
                obs = self._summarize_findings(domain, "cve", ok)

            elif name == "run_zero_day_fuzzer":
                ok = h.run_zero_day_fuzzer(domain, deep=bool(args.get("deep", False)))
                obs = self._summarize_findings(domain, "zero-day", ok)

            elif name == "generate_reports":
                count = h.generate_reports(domain)
                obs = self._summarize_reports(domain, count)

            elif name == "read_autopilot_state":
                obs = self._read_autopilot_state(
                    domain,
                    repo_root=str(args.get("repo_root", "")),
                    memory_dir=str(args.get("memory_dir", "")),
                )

            elif name == "read_guard_status":
                obs = self._read_guard_status(
                    domain,
                    memory_dir=str(args.get("memory_dir", "")),
                )

            elif name == "read_repo_source_summary":
                obs = self._read_repo_source_summary(domain)

            elif name == "read_resume_summary":
                obs = self._read_resume_summary(
                    domain,
                    memory_dir=str(args.get("memory_dir", "")),
                )

            elif name == "read_surface_summary":
                obs = self._read_surface_summary(
                    domain,
                    repo_root=str(args.get("repo_root", "")),
                    memory_dir=str(args.get("memory_dir", "")),
                )

            elif name == "run_intel":
                obs = self._run_intel(
                    domain,
                    tech=str(args.get("tech", "")),
                    program=str(args.get("program", "")),
                    memory_dir=str(args.get("memory_dir", "")),
                )

            elif name == "remember_finding":
                obs = self._remember_finding(
                    domain,
                    target=str(args.get("target", "")),
                    vuln_class=str(args.get("vuln_class", "")),
                    endpoint=str(args.get("endpoint", "")),
                    result=str(args.get("result", "")),
                    severity=str(args.get("severity", "")),
                    payout=args.get("payout", None),
                    technique=str(args.get("technique", "")),
                    notes=str(args.get("notes", "")),
                    tags=args.get("tags", []),
                    tech_stack=args.get("tech_stack", []),
                    memory_dir=str(args.get("memory_dir", "")),
                )

            elif name == "read_recon_summary":
                obs = self._read_recon_files(domain)

            elif name == "read_findings_summary":
                obs = self._read_findings_files(domain)

            elif name == "update_working_memory":
                notes = args.get("notes", "")
                self.memory.working_memory = notes
                self.memory.save()
                return f"Working memory updated ({len(notes)} chars)."

            elif name == "finish":
                return f"FINISH: {args.get('verdict', 'Hunt complete.')}"

            else:
                return f"Unknown tool: {name}"

        except Exception as exc:
            tb = traceback.format_exc()
            return f"Tool {name} raised exception: {exc}\n{tb[:500]}"

        elapsed = round(time.time() - t0, 1)
        obs_full = f"{obs}\n\n[{name} completed in {elapsed}s]"

        # Update memory
        self.memory.add_observation(name, obs_full)
        self.memory.completed_steps.append(name)
        self.memory.step_count += 1

        # Classify any critical/high findings into findings_log
        self._classify_obs(name, obs_full)
        self.memory.save()

        return obs_full

    # ── Observation formatters ──────────────────────────────────────────────

    def _summarize_recon(self, domain: str, ok: bool) -> str:
        h = _h()
        lines = [f"run_recon: {'OK' if ok else 'PARTIAL'}"]
        recon_dir = h._resolve_recon_dir(domain)

        live_urls = h._collect_live_urls(domain)
        if live_urls:
            lines.append(f"Live hosts: {len(live_urls)}")

        for fn in ("resolved.txt", "all.txt"):
            fp = os.path.join(recon_dir, fn)
            if os.path.isfile(fp):
                count = sum(1 for _ in open(fp) if _.strip())
                lines.append(f"Subdomains: {count}")
                break

        techs = h._extract_recon_tech_stack(domain, limit=10)
        if techs:
            lines.append(f"Tech detected: {', '.join(techs)}")

        all_urls = h._collect_all_urls(domain)
        if all_urls:
            lines.append(f"All URLs: {len(all_urls)}")

        param_urls = h._collect_param_urls(domain)
        if param_urls:
            lines.append(f"Parameterized URLs: {len(param_urls)}")

        api_urls = h._collect_api_endpoints(domain)
        if api_urls:
            lines.append(f"API endpoints: {len(api_urls)}")

        js_urls = h._collect_js_urls(domain)
        if js_urls:
            lines.append(f"JavaScript assets: {len(js_urls)}")

        return "\n".join(lines)

    def _summarize_tools(self, installed: list[str], missing: list[str]) -> str:
        lines = [f"check_tools: {len(installed)} installed, {len(missing)} missing"]
        if installed:
            lines.append("Installed: " + ", ".join(installed[:12]))
        if missing:
            lines.append("Missing: " + ", ".join(missing[:12]))
        return "\n".join(lines)

    def _summarize_findings(self, domain: str, label: str, ok: bool) -> str:
        h = _h()
        findings_dir = h._resolve_findings_dir(domain, create=False)
        lines = [f"{label}: {'OK' if ok else 'ran (check manually)'}"]

        # Walk findings dir for any .txt with content
        if findings_dir and os.path.isdir(findings_dir):
            for root, _, files in os.walk(findings_dir):
                for fn in files:
                    if not fn.endswith(".txt"):
                        continue
                    fp = os.path.join(root, fn)
                    try:
                        content = Path(fp).read_text(errors="replace")
                        if any(kw in content.lower() for kw in
                               ("critical", "high", "vulnerable", "injectable",
                                "rce", "sqli", "open redirect", "exposed", "default cred")):
                            head = content[:400].replace("\n", " ")
                            lines.append(f"  [{fn}] {head}")
                    except Exception:
                        pass

        if len(lines) == 1:
            lines.append("  No HIGH/CRITICAL findings in artifacts (check logs above for details).")
        return "\n".join(lines[:20])

    def _summarize_repo_source(self, domain: str, ok: bool) -> str:
        h = _h()
        findings_dir = h._resolve_findings_dir(domain, create=False)
        exposure_dir = os.path.join(findings_dir, "exposure") if findings_dir else ""
        lines = [f"run_repo_source_hunt: {'OK' if ok else 'confirmation required / check artifacts'}"]

        meta_path = os.path.join(exposure_dir, "repo_source_meta.json")
        if os.path.isfile(meta_path):
            try:
                meta = json.loads(Path(meta_path).read_text())
                lines.append(
                    "  source={source_kind} files={file_count} size={size_bytes} clone={clone_performed}".format(**meta)
                )
            except Exception:
                pass

        for filename in ("repo_secrets.json", "repo_ci_findings.json"):
            file_path = os.path.join(exposure_dir, filename)
            if not os.path.isfile(file_path):
                continue
            try:
                payload = json.loads(Path(file_path).read_text())
                lines.append(f"  {filename}: {len(payload)} findings")
            except Exception:
                pass

        summary_path = os.path.join(exposure_dir, "repo_summary.md")
        if os.path.isfile(summary_path):
            summary = Path(summary_path).read_text(errors="replace")[:400].replace("\n", " ")
            lines.append(f"  [repo_summary.md] {summary}")

        return "\n".join(lines)

    def _summarize_reports(self, domain: str, count: int) -> str:
        h = _h()
        report_dir = os.path.join(h.REPORTS_DIR, domain)
        lines = [f"generate_reports: {count} report(s) generated"]
        if os.path.isdir(report_dir):
            reports = sorted(
                fn for fn in os.listdir(report_dir)
                if fn.endswith(".md") and fn != "SUMMARY.md"
            )
            if reports:
                lines.append("Reports: " + ", ".join(reports[:8]))
        return "\n".join(lines)

    def _read_autopilot_state(self, domain: str, repo_root: str = "", memory_dir: str = "") -> str:
        from tools.autopilot_state import build_autopilot_state, format_autopilot_state

        resolved_repo_root = repo_root or _h().BASE_DIR
        resolved_memory_dir = self._resolve_memory_dir(memory_dir)
        state = build_autopilot_state(resolved_repo_root, domain, memory_dir=resolved_memory_dir)
        return format_autopilot_state(state)

    def _read_guard_status(self, domain: str, memory_dir: str = "") -> str:
        from tools.request_guard import format_guard_output, load_guard_status

        resolved_memory_dir = self._resolve_memory_dir(memory_dir)
        status = load_guard_status(resolved_memory_dir, domain)
        return format_guard_output(status, "status")

    def _read_repo_source_summary(self, domain: str) -> str:
        h = _h()
        findings_dir = h._resolve_findings_dir(domain, create=False)
        exposure_dir = os.path.join(findings_dir, "exposure") if findings_dir else ""
        if not exposure_dir or not os.path.isdir(exposure_dir):
            return f"No repo source artifacts found for {domain}."
        return self._summarize_repo_source(domain, ok=True)

    def _read_resume_summary(self, domain: str, memory_dir: str = "") -> str:
        from tools.resume import format_resume_output, load_resume_summary

        resolved_memory_dir = self._resolve_memory_dir(memory_dir)
        summary = load_resume_summary(resolved_memory_dir, domain)
        return format_resume_output(summary, domain)

    def _read_surface_summary(self, domain: str, repo_root: str = "", memory_dir: str = "") -> str:
        from tools.surface import format_surface_output, load_surface_context, rank_surface

        resolved_repo_root = repo_root or _h().BASE_DIR
        resolved_memory_dir = self._resolve_memory_dir(memory_dir)
        context = load_surface_context(resolved_repo_root, domain, memory_dir=resolved_memory_dir)
        ranked = rank_surface(context)
        return format_surface_output(ranked, domain)

    def _run_intel(self, domain: str, tech: str = "", program: str = "", memory_dir: str = "") -> str:
        from tools.intel_engine import (
            fetch_all_intel,
            format_output,
            load_memory_context,
            prioritize_intel,
        )

        resolved_memory_dir = self._resolve_memory_dir(memory_dir)
        memory = load_memory_context(resolved_memory_dir, domain)

        techs = [item.strip().lower() for item in tech.split(",") if item.strip()]
        for item in memory.get("tech_stack", []):
            normalized = str(item).strip().lower()
            if normalized and normalized not in techs:
                techs.append(normalized)
        for item in _h()._extract_recon_tech_stack(domain, limit=12):
            normalized = str(item).strip().lower()
            if normalized and normalized not in techs:
                techs.append(normalized)

        if not techs:
            return (
                f"No tech stack available for {domain}.\n"
                f"Run read_recon_summary or pass tech explicitly before run_intel."
            )

        results = fetch_all_intel(techs, domain, program)
        intel = prioritize_intel(results, memory)
        return format_output(domain, intel)

    def _remember_finding(
        self,
        domain: str,
        *,
        target: str = "",
        vuln_class: str = "",
        endpoint: str = "",
        result: str = "",
        severity: str = "",
        payout: Any = None,
        technique: str = "",
        notes: str = "",
        tags: Any = None,
        tech_stack: Any = None,
        memory_dir: str = "",
    ) -> str:
        from tools.remember import remember_finding

        resolved_target = target or domain
        if not vuln_class or not endpoint or not result:
            return "ERROR: remember_finding requires vuln_class, endpoint, and result."

        resolved_memory_dir = self._resolve_memory_dir(memory_dir)
        resolved_tags = tags if isinstance(tags, list) else []
        resolved_tech_stack = tech_stack if isinstance(tech_stack, list) else []
        numeric_payout = None if payout in ("", None) else float(payout)

        summary = remember_finding(
            memory_dir=resolved_memory_dir,
            target=resolved_target,
            vuln_class=vuln_class,
            endpoint=endpoint,
            result=result,
            severity=severity or None,
            payout=numeric_payout,
            technique=technique or None,
            notes=notes or None,
            tags=resolved_tags,
            tech_stack=resolved_tech_stack,
        )

        lines = [
            "REMEMBERED",
            f"Target: {summary['target']}",
            f"Endpoint: {summary['endpoint']}",
            f"Journal: {'yes' if summary['journal_saved'] else 'no'}",
            f"Target profile updated: {'yes' if summary['finding_saved'] or summary['journal_saved'] else 'no'}",
            f"Pattern saved: {'yes' if summary['pattern_saved'] else 'no'}",
        ]
        if summary["tech_stack"]:
            lines.append(f"Tech stack: {', '.join(summary['tech_stack'])}")
        return "\n".join(lines)

    def _summarize_params(self, domain: str, ok: bool) -> str:
        h = _h()
        recon_dir  = h._resolve_recon_dir(domain)
        params_dir = os.path.join(recon_dir, "params")
        lines = [f"run_param_discovery: {'OK' if ok else 'partial'}"]

        interesting_path = os.path.join(params_dir, "interesting_params.txt")
        if os.path.isfile(interesting_path):
            count = sum(1 for _ in open(interesting_path) if _.strip())
            lines.append(f"  interesting_params.txt: {count} candidates")

        arjun_outputs = sorted(
            fn for fn in os.listdir(params_dir)
            if fn.startswith("arjun_") and fn.endswith(".txt")
        ) if os.path.isdir(params_dir) else []
        if arjun_outputs:
            lines.append(f"  arjun outputs: {len(arjun_outputs)} files")

        if len(lines) == 1:
            lines.append("  No parameter discovery artifacts found.")
        return "\n".join(lines)

    def _summarize_post_params(self, domain: str, ok: bool) -> str:
        h = _h()
        recon_dir  = h._resolve_recon_dir(domain)
        params_dir = os.path.join(recon_dir, "params")
        lines = [f"run_post_param_discovery: {'found POST params' if ok else 'no POST params found'}"]
        fp = os.path.join(params_dir, "post_params.json")
        if os.path.isfile(fp):
            try:
                data = json.loads(Path(fp).read_text())
                for url, info in list(data.items())[:8]:
                    params = ", ".join(info.get("params", [])[:6])
                    lines.append(f"  POST {url}  →  [{params}]")
            except Exception:
                pass
        return "\n".join(lines)

    def _read_recon_files(self, domain: str) -> str:
        h = _h()
        parts = []

        live_urls = h._collect_live_urls(domain)
        if live_urls:
            parts.append(
                f"=== Live hosts ({len(live_urls)} total) ===\n" + "\n".join(live_urls[:20])
            )

        techs = h._extract_recon_tech_stack(domain, limit=12)
        if techs:
            parts.append("=== Tech stack ===\n" + "\n".join(techs))

        api_urls = h._collect_api_endpoints(domain)
        if api_urls:
            parts.append(
                f"=== API endpoints ({len(api_urls)} total) ===\n" + "\n".join(api_urls[:20])
            )

        param_urls = h._collect_param_urls(domain)
        if param_urls:
            parts.append(
                f"=== Parameterized URLs ({len(param_urls)} total) ===\n" + "\n".join(param_urls[:20])
            )

        js_urls = h._collect_js_urls(domain)
        if js_urls:
            parts.append(
                f"=== JavaScript assets ({len(js_urls)} total) ===\n" + "\n".join(js_urls[:20])
            )

        all_urls = h._collect_all_urls(domain)
        if all_urls:
            parts.append(
                f"=== All URLs ({len(all_urls)} total) ===\n" + "\n".join(all_urls[:20])
            )

        post_params_path = os.path.join(h._resolve_recon_dir(domain), "params", "post_params.json")
        if os.path.isfile(post_params_path):
            try:
                post_params = json.loads(Path(post_params_path).read_text())
                sample = []
                for url, info in list(post_params.items())[:10]:
                    params = ", ".join(info.get("params", [])[:6])
                    sample.append(f"{url} -> {params}")
                if sample:
                    parts.append(
                        f"=== POST params ({len(post_params)} forms) ===\n" + "\n".join(sample)
                    )
            except Exception:
                pass

        findings_dir = h._resolve_findings_dir(domain, create=False)
        exposure_dir = os.path.join(findings_dir, "exposure") if findings_dir else ""
        if exposure_dir and os.path.isdir(exposure_dir):
            known_artifacts = (
                "repo_source_meta.json",
                "repo_secrets.json",
                "repo_ci_findings.json",
                "repo_summary.md",
            )
            if any(os.path.isfile(os.path.join(exposure_dir, name)) for name in known_artifacts):
                parts.append(
                    "=== Repo source artifacts ===\n"
                    "Repository source-hunt artifacts already exist under findings/<target>/exposure.\n"
                    "Use read_repo_source_summary before re-running run_repo_source_hunt."
                )

        return "\n\n".join(parts) if parts else "No recon data found. Run run_recon first."

    def _read_findings_files(self, domain: str) -> str:
        h = _h()
        findings_dir = h._resolve_findings_dir(domain, create=False)
        if not findings_dir or not os.path.isdir(findings_dir):
            return "No findings directory. Run vulnerability scans first."

        parts = []
        exposure_dir = os.path.join(findings_dir, "exposure")
        if os.path.isdir(exposure_dir):
            repo_summary = self._summarize_repo_source(domain, ok=True)
            if repo_summary.strip():
                parts.append("=== repo_source_overview ===\n" + repo_summary)

        for root, _, files in os.walk(findings_dir):
            for fn in sorted(files):
                if not fn.endswith((".txt", ".json", ".md")):
                    continue
                fp = os.path.join(root, fn)
                try:
                    content = Path(fp).read_text(errors="replace")
                    if content.strip():
                        rel = os.path.relpath(fp, findings_dir)
                        parts.append(f"=== {rel} ===\n{content[:800]}")
                except Exception:
                    pass

        if not parts:
            return "Findings directory exists but is empty."
        combined = "\n\n".join(parts)
        # Truncate to avoid blowing context
        if len(combined) > MAX_CTX_CHARS:
            combined = combined[:MAX_CTX_CHARS] + "\n...[truncated]"
        return combined

    def _classify_obs(self, tool: str, obs: str) -> None:
        """Extract severity labels from observation text and add to findings_log."""
        obs_l = obs.lower()
        if any(kw in obs_l for kw in ("rce_confirmed", "injectable", "critical")):
            sev = "CRITICAL"
        elif any(kw in obs_l for kw in ("high", "sql injection", "rce", "default cred")):
            sev = "HIGH"
        elif any(kw in obs_l for kw in ("medium", "exposed", "open redirect", "cors")):
            sev = "MEDIUM"
        elif any(kw in obs_l for kw in ("low", "info")):
            sev = "LOW"
        else:
            return  # not a finding, skip

        # Take first relevant line as summary
        for ln in obs.splitlines():
            if any(kw in ln.lower() for kw in
                   ("critical", "high", "injectable", "rce", "exposed", "found", "medium", "sql")):
                self.memory.add_finding(tool, sev, ln.strip()[:300])
                break


# ──────────────────────────────────────────────────────────────────────────────
#  Core ReAct agent  (Ollama native tool calling)
# ──────────────────────────────────────────────────────────────────────────────

# ──────────────────────────────────────────────────────────────────────────────
#  Loop Detector  (ctf-agent technique: signature hashing, sliding window 12)
# ──────────────────────────────────────────────────────────────────────────────

class LoopDetector:
    """
    Detects when the agent is repeating the same tool call in a loop.
    Sliding window of last 12 tool signatures.
    Warn at 3 repetitions, force direction change at 5.
    Signature = tool_name + first 300 chars of serialised args.
    """
    WINDOW = 12
    WARN_AT  = 3
    BREAK_AT = 5

    def __init__(self):
        self._history: list[str] = []
        self._counts:  dict[str, int] = {}

    def record(self, tool: str, args: dict) -> tuple[bool, bool]:
        """
        Record a tool call. Returns (warn, must_break).
        warn=True at WARN_AT repeats; must_break=True at BREAK_AT.
        """
        sig = tool + ":" + json.dumps(args, sort_keys=True)[:300]
        self._history.append(sig)
        if len(self._history) > self.WINDOW:
            evicted = self._history.pop(0)
            self._counts[evicted] = max(0, self._counts.get(evicted, 0) - 1)
        self._counts[sig] = self._counts.get(sig, 0) + 1
        n = self._counts[sig]
        return n >= self.WARN_AT, n >= self.BREAK_AT

    def reset(self) -> None:
        self._history.clear()
        self._counts.clear()


# ──────────────────────────────────────────────────────────────────────────────
#  JSONL Tracer  (ctf-agent technique: append-only, immediate flush, tail -f)
# ──────────────────────────────────────────────────────────────────────────────

class AgentTracer:
    """
    Append-only JSONL event log — one JSON object per line, flushed immediately.
    `tail -f session.jsonl` gives live stream of what the agent is doing.
    """

    def __init__(self, log_path: str):
        self.log_path = log_path
        Path(log_path).parent.mkdir(parents=True, exist_ok=True)
        self._f = open(log_path, "a", buffering=1)  # line-buffered

    def _write(self, event: dict) -> None:
        event.setdefault("ts", datetime.now().isoformat())
        self._f.write(json.dumps(event) + "\n")
        self._f.flush()

    def tool_call(self, tool: str, args: dict, step: int) -> None:
        self._write({"event": "tool_call", "step": step, "tool": tool, "args": args})

    def tool_result(self, tool: str, result: str, elapsed: float, step: int) -> None:
        self._write({"event": "tool_result", "step": step, "tool": tool,
                     "elapsed_s": elapsed, "result_preview": result[:400]})

    def loop_warn(self, tool: str, count: int, step: int) -> None:
        self._write({"event": "loop_warn", "step": step, "tool": tool, "count": count})

    def loop_break(self, tool: str, step: int) -> None:
        self._write({"event": "loop_break", "step": step, "tool": tool})

    def bump(self, message: str, step: int) -> None:
        self._write({"event": "bump", "step": step, "message": message})

    def finding(self, severity: str, tool: str, text: str) -> None:
        self._write({"event": "finding", "severity": severity, "tool": tool, "text": text[:300]})

    def finish(self, verdict: str, step: int, elapsed_mins: float) -> None:
        self._write({"event": "finish", "step": step,
                     "elapsed_mins": elapsed_mins, "verdict": verdict})

    def close(self) -> None:
        self._f.close()


# ──────────────────────────────────────────────────────────────────────────────
#  Multi-model racer  (ctf-agent: asyncio FIRST_COMPLETED pattern)
# ──────────────────────────────────────────────────────────────────────────────

def race_analysis(prompt: str, models: list[str], client,
                  system: str = "", timeout: int = 120) -> str:
    """
    Ask multiple Ollama models the same analysis question.
    Return whichever completes first with a non-empty answer.
    Used for: triage decisions, next-action advice, finding classification.
    Falls back to sequential if only one model available.
    """
    import threading

    result_holder: dict[str, str] = {}
    done_event = threading.Event()

    def _call(model: str) -> None:
        try:
            resp = client.chat(
                model=model,
                messages=[
                    {"role": "system", "content": system or AGENT_SYSTEM},
                    {"role": "user",   "content": prompt},
                ],
                options={"num_predict": 800, "temperature": 0.1, "num_ctx": 8192},
            )
            text = (resp.get("message", {}).get("content") or "").strip()
            if text and not done_event.is_set():
                result_holder["winner"] = model
                result_holder["text"]   = text
                done_event.set()
        except Exception:
            pass

    threads = [threading.Thread(target=_call, args=(m,), daemon=True) for m in models]
    for t in threads:
        t.start()
    done_event.wait(timeout=timeout)

    if "text" in result_holder:
        winner = result_holder["winner"]
        print(f"{DIM}[Race] Winner: {winner}{NC}", flush=True)
        return result_holder["text"]

    # Sequential fallback
    for m in models:
        try:
            resp = client.chat(
                model=m,
                messages=[
                    {"role": "system", "content": system or AGENT_SYSTEM},
                    {"role": "user",   "content": prompt},
                ],
                options={"num_predict": 800, "temperature": 0.1, "num_ctx": 8192},
            )
            text = (resp.get("message", {}).get("content") or "").strip()
            if text:
                return text
        except Exception:
            continue
    return ""


def _build_agent_system(ctf_mode: bool = False, autopilot_mode: str = "paranoid") -> str:
    autopilot_mode = _normalize_autopilot_mode(autopilot_mode)
    mode_block = (
        "MODE:\n"
        "- Local CTF practice is enabled.\n"
        "- All provided targets are considered in-scope.\n"
        "- Do not spend time on program acceptance, bounty eligibility, or scope validation.\n"
        "- Focus on exploitation, root cause, and practical attack paths.\n"
    ) if ctf_mode else (
        "MODE:\n"
        "- You are operating within an authorized bug bounty program or VAPT engagement.\n"
        "- Stay within the provided target and prefer realistic, reportable findings.\n"
    )

    checkpoint_block = {
        "paranoid": (
            "CHECKPOINT MODE:\n"
            "- Checkpoint mode: paranoid.\n"
            "- Favor frequent checkpoints and conservative exploration.\n"
            "- Summarize meaningful signals early and avoid skipping suspicious branches.\n"
        ),
        "normal": (
            "CHECKPOINT MODE:\n"
            "- Checkpoint mode: normal.\n"
            "- Batch related findings before checkpointing.\n"
            "- Balance coverage with momentum; rotate when a branch stalls.\n"
        ),
        "yolo": (
            "CHECKPOINT MODE:\n"
            "- Checkpoint mode: yolo.\n"
            "- Keep moving until the surface is exhausted or the time budget is low.\n"
            "- Minimize checkpoints, but still preserve evidence and clear operator handoff notes.\n"
        ),
    }[autopilot_mode]

    return f"""\
You are an elite autonomous security hunter. You have a set of tools that execute real security scans. Use them strategically.

{mode_block}
{checkpoint_block}
CORE RULES:
1. If scans fail unexpectedly or the environment looks incomplete, use check_tools once to understand local capability limits.
2. Prefer read_autopilot_state early to see whether recon/memory already exist, which targets are hottest, and whether any host is cooling down.
3. If no recon data exists yet, start with run_recon. After recon, use read_autopilot_state or read_surface_summary before choosing next tool.
4. If read_autopilot_state or bootstrap context shows cooling/tripped hosts, avoid hammering them and prefer the highest-score non-tripped target first.
5. If active testing starts returning 403/429/timeouts or progress stalls, use read_guard_status to inspect breaker/cooldown state before retrying hosts.
6. If repository source-hunt artifacts already exist for this target, use read_repo_source_summary before re-running run_repo_source_hunt.
7. Prioritize by impact: CMS exploits > RCE > SQLi > IDOR/auth bypass > secrets > info.
8. If Drupal or WordPress is detected → run_cms_exploit immediately. If any stack is clearly identified, run_cve_hunt.
9. If Java/Tomcat/JBoss/Spring is detected → run_rce_scan + run_post_param_discovery.
10. If JS assets exist → run_js_analysis, then run_secret_hunt if secrets/tokens/config leaks are plausible.
11. If API endpoints or numeric-object URLs exist → run_api_fuzz. If authenticated surfaces exist → run_cors_check.
12. If parameterized URLs found → run_param_discovery and run_sqlmap_targeted. Use run_sqlmap_on_file for specific raw requests.
13. If JWT tokens appear in recon data → run_jwt_audit.
14. When standard scans have plateaued but attack surface remains, use run_zero_day_fuzzer.
15. Generate reports with generate_reports before finish when findings or useful artifacts exist.
16. Maintain your notes via update_working_memory after each significant discovery.
17. Call finish when: all high-priority tools done, time running low, or no new attack surface.
18. DO NOT repeat a tool that already completed in this session unless explicitly justified.

Think step by step. Pick the highest-impact next action given what you know."""


AGENT_SYSTEM = _build_agent_system(ctf_mode=False, autopilot_mode="paranoid")


class ReActAgent:
    """
    Built-in ReAct loop using Ollama native tool calling.
    Works without LangGraph installed — just needs `pip install ollama`.
    """

    MIN_STEPS_BEFORE_FINISH = 6  # persistence: must run at least N tools before finish allowed

    def __init__(self, domain: str, memory: HuntMemory,
                 dispatcher: ToolDispatcher,
                 max_steps: int = 20,
                 time_budget_hours: float = 2.0,
                 model: str | None = None,
                 tracer: AgentTracer | None = None,
                 ctf_mode: bool = False,
                 autopilot_mode: str = "paranoid"):
        self.domain     = domain
        self.memory     = memory
        self.dispatcher = dispatcher
        self.max_steps  = max_steps
        self.time_start = time.time()
        self.time_budget_secs = time_budget_hours * 3600
        self.done       = False
        self.verdict    = ""
        self.ctf_mode   = ctf_mode
        self.autopilot_mode = _normalize_autopilot_mode(autopilot_mode)
        self.min_steps_before_finish = _finish_floor_for_mode(self.autopilot_mode)
        self.system_prompt = _build_agent_system(
            ctf_mode=ctf_mode,
            autopilot_mode=self.autopilot_mode,
        )

        # ctf-agent techniques
        self.loop_detector = LoopDetector()
        self.tracer        = tracer  # set externally after session_file is known
        self.bump_file     = ""      # set by run_agent_hunt — path to bump file

        # racing models (analysis + triage) — baron-llm races qwen3 on quick decisions
        self._race_models: list[str] = []

        if not _OLLAMA_OK:
            raise RuntimeError("Ollama Python package not installed: pip install ollama")

        self.client = _ollama_lib.Client(host=OLLAMA_HOST)
        self.model  = model or self._pick_tool_capable_model()
        if not self.model:
            raise RuntimeError("No Ollama model available. Pull one: ollama pull qwen2.5:32b")

        # Build race roster: primary model + baron-llm if available and different
        try:
            available = [m.model for m in self.client.list().models]
            if "baron-llm:latest" in available and "baron-llm:latest" != self.model:
                self._race_models = [self.model, "baron-llm:latest"]
            else:
                self._race_models = [self.model]
        except Exception:
            self._race_models = [self.model]

        print(f"{GREEN}[Agent] ReAct loop online — model: {BOLD}{self.model}{NC}", flush=True)
        race_note = f"  race_models={self._race_models}" if len(self._race_models) > 1 else ""
        print(f"{DIM}[Agent] max_steps={max_steps}  budget={time_budget_hours}h  "
              f"tool_calling=native{race_note}{NC}", flush=True)
        print(f"{DIM}[Agent] checkpoint_mode={self.autopilot_mode}  "
              f"finish_floor={self.min_steps_before_finish}{NC}", flush=True)
        if self.ctf_mode:
            print(f"{YELLOW}[Agent] CTF mode enabled — scope/program checks are skipped.{NC}", flush=True)

    def _pick_tool_capable_model(self) -> str | None:
        """Prefer models with confirmed Ollama tool-calling support."""
        tool_capable_first = [
            "qwen3-coder-64k:latest",
            "qwen3-coder:30b",
            "qwen2.5:32b",
            "qwen2.5-coder:32b",
            "qwen3:30b-a3b",
            "qwen3:14b",
            "qwen3:8b",
            "mistral:7b-instruct-v0.3-q8_0",
        ]
        try:
            available = [m.model for m in self.client.list().models]
        except Exception:
            return None

        for pref in tool_capable_first:
            if pref in available:
                return pref
        # Fall back to first available
        return available[0] if available else None

    def _build_context(self) -> str:
        """Build the current state block that prefixes every LLM message."""
        elapsed_mins = round((time.time() - self.time_start) / 60, 1)
        budget_mins  = round(self.time_budget_secs / 60, 1)
        remaining    = round((self.time_budget_secs - (time.time() - self.time_start)) / 60, 1)

        completed = list(dict.fromkeys(self.memory.completed_steps))
        ctx_parts = [
            f"## Autonomous Hunt — {self.domain}",
            f"Mode: {'CTF' if self.ctf_mode else 'Bug bounty/VAPT'}",
            f"Checkpoint mode: {self.autopilot_mode}",
            f"Step {self.memory.step_count + 1}/{self.max_steps}  "
            f"| Elapsed {elapsed_mins}m / {budget_mins}m budget  "
            f"| {remaining}m remaining",
            "",
            f"## Completed steps ({len(completed)})",
            ", ".join(completed) if completed else "(none yet)",
            "",
        ]
        bootstrap = _active_bootstrap_context(self.memory)
        if bootstrap:
            ctx_parts.extend([
                "## Bootstrap focus",
                bootstrap,
                "",
            ])
        ctx_parts.extend([
            "## Working memory (your notes)",
            self.memory.working_memory or "(empty — use update_working_memory to take notes)",
            "",
            "## Findings so far",
            self.memory.findings_summary(),
            "",
            "## Recent tool outputs (last 3)",
            self.memory.recent_observations(3),
        ])
        return "\n".join(ctx_parts)

    def _check_bump(self) -> str | None:
        """Check if operator has injected guidance via bump file."""
        if not self.bump_file or not os.path.isfile(self.bump_file):
            return None
        try:
            msg = Path(self.bump_file).read_text().strip()
            if msg:
                Path(self.bump_file).write_text("")  # consume
                return msg
        except Exception:
            pass
        return None

    def step(self) -> str | None:
        """Execute one ReAct step. Returns observation string or None if finished."""
        if self.done:
            return None

        time_left = self.time_budget_secs - (time.time() - self.time_start)
        if time_left < 60:
            print(f"{YELLOW}[Agent] Time budget exhausted — stopping.{NC}", flush=True)
            self.done = True
            return None

        # ── Check operator bump (guidance injection mid-run) ─────────────
        bump_msg = self._check_bump()
        if bump_msg:
            print(f"{YELLOW}[Agent] BUMP received: {bump_msg}{NC}", flush=True)
            if self.tracer:
                self.tracer.bump(bump_msg, self.memory.step_count)
            self.loop_detector.reset()  # fresh start after guidance
            self.memory.working_memory += f"\n\n[OPERATOR GUIDANCE] {bump_msg}"
            self.memory.save()

        context  = self._build_context()
        user_msg = f"{context}\n\nWhat is the best next action? Call the appropriate tool."

        print(f"\n{CYAN}{'─'*60}{NC}", flush=True)
        print(f"{BOLD}[Agent] Step {self.memory.step_count + 1} — calling LLM...{NC}", flush=True)

        try:
            response = self.client.chat(
                model=self.model,
                messages=[
                    {"role": "system",    "content": self.system_prompt},
                    {"role": "user",      "content": user_msg},
                ],
                tools=TOOLS,
                options={
                    "num_ctx":     16384,
                    "num_predict": 1024,
                    "temperature": 0.1,
                },
            )
        except Exception as e:
            print(f"{RED}[Agent] LLM call failed: {e}{NC}", flush=True)
            return f"LLM error: {e}"

        msg = response.get("message", {})

        # ── Native tool calling path ─────────────────────────────────────
        tool_calls = msg.get("tool_calls", [])
        if tool_calls:
            results = []
            for tc in tool_calls:
                fn   = tc.get("function", {})
                name = fn.get("name", "")
                args = fn.get("arguments", {})
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except Exception:
                        args = {}

                # ── Persistence enforcement: block early finish ──────────
                if name == "finish" and self.memory.step_count < self.min_steps_before_finish:
                    remaining_needed = self.min_steps_before_finish - self.memory.step_count
                    print(f"{YELLOW}[Agent] Finish blocked — only {self.memory.step_count} steps done, "
                          f"need {remaining_needed} more. Continuing...{NC}", flush=True)
                    results.append(
                        f"[SYSTEM] Too early to finish. You have only run "
                        f"{self.memory.step_count} tools. Run at least "
                        f"{remaining_needed} more high-impact tools before concluding."
                    )
                    continue

                # ── Loop detection ───────────────────────────────────────
                warn, must_break = self.loop_detector.record(name, args)
                if must_break:
                    print(f"{RED}[Agent] Loop detected on '{name}' — forcing direction change{NC}",
                          flush=True)
                    if self.tracer:
                        self.tracer.loop_break(name, self.memory.step_count)
                    self.loop_detector.reset()
                    results.append(
                        f"[SYSTEM] Loop detected: '{name}' called 5+ times with identical args. "
                        f"You MUST switch strategy. Try a completely different tool or angle. "
                        f"What have you NOT tried yet?"
                    )
                    continue
                if warn:
                    print(f"{YELLOW}[Agent] Loop warning: '{name}' repeated — consider switching{NC}",
                          flush=True)
                    if self.tracer:
                        self.tracer.loop_warn(name, LoopDetector.WARN_AT, self.memory.step_count)

                print(f"{MAGENTA}[Agent] Tool: {BOLD}{name}{NC}{MAGENTA}  args={json.dumps(args)}{NC}",
                      flush=True)
                if self.tracer:
                    self.tracer.tool_call(name, args, self.memory.step_count)

                t0  = time.time()
                obs = self.dispatcher.dispatch(name, args)
                elapsed = round(time.time() - t0, 1)

                if self.tracer:
                    self.tracer.tool_result(name, obs, elapsed, self.memory.step_count)

                results.append(obs)

                if name == "finish":
                    self.done    = True
                    self.verdict = args.get("verdict", "")
                    if self.tracer:
                        self.tracer.finish(self.verdict, self.memory.step_count,
                                           round((time.time() - self.time_start) / 60, 1))

            return "\n\n---\n\n".join(results)

        # ── Text-based fallback (model didn't use tool calling) ──────────
        content = msg.get("content", "")
        if content:
            print(f"{DIM}[Agent] LLM text response (no tool call):\n{content[:300]}{NC}",
                  flush=True)
            # Try to parse ReAct-format: Action: tool_name / Action Input: {...}
            parsed = self._parse_react_text(content)
            if parsed:
                name, args = parsed
                print(f"{MAGENTA}[Agent] Parsed from text: {name}{NC}", flush=True)
                obs = self.dispatcher.dispatch(name, args)
                if name == "finish":
                    self.done    = True
                    self.verdict = args.get("verdict", "")
                return obs

        # LLM produced nothing useful — nudge it
        self.memory.step_count += 1
        return "(LLM produced no tool call — will retry next step)"

    def _parse_react_text(self, text: str) -> tuple[str, dict] | None:
        """Parse old-style ReAct text format as fallback for non-tool-calling models."""
        import re
        # Match: Action: tool_name\nAction Input: {...}
        m = re.search(
            r"Action:\s*(\w+)\s*\nAction\s+Input:\s*(\{.*?\})",
            text, re.DOTALL
        )
        if m:
            name = m.group(1)
            try:
                args = json.loads(m.group(2))
            except Exception:
                args = {}
            if name in TOOL_NAMES:
                return name, args

        # Simpler: just "Action: tool_name" with no args
        m2 = re.search(r"Action:\s*(\w+)", text)
        if m2:
            name = m2.group(1)
            if name in TOOL_NAMES:
                return name, {}

        return None

    def run(self) -> dict:
        """Run the full ReAct loop until done or max_steps reached."""
        print(f"\n{BOLD}{CYAN}╔══════════════════════════════════════════╗{NC}")
        print(f"{BOLD}{CYAN}║  ReAct Hunt Agent — {self.domain:<20}  ║{NC}")
        print(f"{BOLD}{CYAN}╚══════════════════════════════════════════╝{NC}\n")

        for i in range(self.max_steps):
            if self.done:
                break

            obs = self.step()
            if obs:
                # Print first 500 chars of observation
                preview = obs[:500] + ("..." if len(obs) > 500 else "")
                print(f"{DIM}[Observation]\n{preview}{NC}\n", flush=True)

        if not self.done:
            print(f"{YELLOW}[Agent] Max steps ({self.max_steps}) reached.{NC}", flush=True)

        elapsed = round((time.time() - self.time_start) / 60, 1)
        print(f"\n{GREEN}[Agent] Hunt complete. ({elapsed} min){NC}")
        print(f"  Steps executed:  {self.memory.step_count}")
        print(f"  Completed tools: {', '.join(dict.fromkeys(self.memory.completed_steps))}")
        print(f"  Findings:        {len(self.memory.findings_log)}")
        print(f"  Checkpoint mode: {self.autopilot_mode}")
        if self.tracer:
            print(f"  Trace log:       {self.tracer.log_path}")
        if self.bump_file:
            print(f"  Bump file:       {self.bump_file}")
        if self.verdict:
            print(f"  Verdict:         {self.verdict}")

        return {
            "domain":           self.domain,
            "success":          True,
            "model":            self.model,
            "steps":            self.memory.step_count,
            "completed_steps":  list(dict.fromkeys(self.memory.completed_steps)),
            "reports":          len(self.memory.findings_log),
            "findings":         len(self.memory.findings_log),
            "findings_log":     self.memory.findings_log,
            "working_memory":   self.memory.working_memory,
            "verdict":          self.verdict,
            "session_file":     self.memory.session_file,
            "autopilot_mode":   self.autopilot_mode,
            **_phase_flags(self.memory.completed_steps),
        }


# ──────────────────────────────────────────────────────────────────────────────
#  LangGraph agent  (optional — requires: pip install langgraph langchain-ollama)
# ──────────────────────────────────────────────────────────────────────────────

def build_langgraph_agent(domain: str, dispatcher: ToolDispatcher,
                           memory: HuntMemory, model: str,
                           max_steps: int = 20,
                           ctf_mode: bool = False,
                           autopilot_mode: str = "paranoid"):
    """
    Build a real LangGraph ReAct agent.
    State: MessagesState (list of messages)
    Nodes: agent (LLM) → tools (ToolNode) → back to agent
    Edges: tools_condition → tool node or END
    """
    if not _LANGGRAPH_OK:
        raise ImportError(
            "LangGraph not installed. Run:\n"
            "  pip install langgraph langchain-ollama\n"
            "Or use the built-in ReAct loop (default, no extra deps)."
        )

    from typing import TypedDict, Annotated
    from langgraph.graph import StateGraph, END
    from langgraph.graph.message import add_messages
    from langgraph.prebuilt import ToolNode, tools_condition
    from langchain_core.messages import HumanMessage, SystemMessage, AIMessage
    from langchain_core.tools import tool as lc_tool, StructuredTool
    import inspect
    system_prompt = _build_agent_system(
        ctf_mode=ctf_mode,
        autopilot_mode=autopilot_mode,
    )

    # ── Wrap dispatcher calls as LangChain tools ──────────────────────────
    lc_tools = []
    for tool_spec in TOOLS:
        fn_spec = tool_spec["function"]
        tool_name = fn_spec["name"]
        tool_desc = fn_spec["description"]
        props     = fn_spec["parameters"].get("properties", {})

        # Create a closure that captures tool_name
        def _make_tool(tname):
            def _tool_fn(**kwargs):
                return dispatcher.dispatch(tname, kwargs)
            _tool_fn.__name__ = tname
            _tool_fn.__doc__  = tool_desc
            return lc_tool(_tool_fn)

        lc_tools.append(_make_tool(tool_name))

    # ── LLM with tools bound ──────────────────────────────────────────────
    llm = ChatOllama(
        model=model,
        base_url=OLLAMA_HOST,
        temperature=0.1,
        num_ctx=16384,
    )
    llm_with_tools = llm.bind_tools(lc_tools)

    # ── State ──────────────────────────────────────────────────────────────
    class HuntState(TypedDict):
        messages: Annotated[list, add_messages]

    # ── Graph nodes ────────────────────────────────────────────────────────
    def agent_node(state: HuntState) -> HuntState:
        context = f"Target: {domain}\n\n" + _build_context_for_langgraph(domain, memory)
        # Prepend system + context to messages if first call
        msgs = state["messages"]
        if not any(isinstance(m, SystemMessage) for m in msgs):
            msgs = [SystemMessage(content=system_prompt),
                    HumanMessage(content=context)] + list(msgs)
        response = llm_with_tools.invoke(msgs)
        # Check finish signal
        if hasattr(response, "tool_calls"):
            for tc in (response.tool_calls or []):
                if tc.get("name") == "finish":
                    memory.working_memory += f"\n\nFINISHED: {tc.get('args', {}).get('verdict', '')}"
        return {"messages": [response]}

    tool_node = ToolNode(lc_tools)

    def should_continue(state: HuntState):
        last = state["messages"][-1]
        if not hasattr(last, "tool_calls") or not last.tool_calls:
            return END
        if any(tc.get("name") == "finish" for tc in last.tool_calls):
            return END
        if memory.step_count >= max_steps:
            return END
        return "tools"

    # ── Build graph ────────────────────────────────────────────────────────
    graph = StateGraph(HuntState)
    graph.add_node("agent", agent_node)
    graph.add_node("tools", tool_node)
    graph.set_entry_point("agent")
    graph.add_conditional_edges("agent", should_continue, {"tools": "tools", END: END})
    graph.add_edge("tools", "agent")

    return graph.compile()


def _build_context_for_langgraph(domain: str, memory: HuntMemory) -> str:
    """Same context builder used by LangGraph agent node."""
    completed = list(dict.fromkeys(memory.completed_steps))
    parts = [f"Completed steps: {', '.join(completed) or 'none'}\n"]
    bootstrap = _active_bootstrap_context(memory)
    if bootstrap:
        parts.append(f"Bootstrap:\n{bootstrap}\n")
    parts.append(f"Working memory:\n{memory.working_memory or '(empty)'}\n")
    parts.append(f"Findings so far:\n{memory.findings_summary()}\n")
    parts.append(f"Recent observations:\n{memory.recent_observations(2)}")
    return "\n".join(parts)


def _active_bootstrap_context(memory: HuntMemory) -> str:
    """Only inject bootstrap guidance on the first step to cap token cost."""
    if int(getattr(memory, "step_count", 0) or 0) > 0:
        return ""
    return str(getattr(memory, "bootstrap_context", "") or "").strip()


def _build_agent_bootstrap_context(
    domain: str,
    *,
    repo_root: str = "",
    memory_dir: str = "",
) -> str:
    """Build a concise runtime bootstrap block from autopilot/resume state."""
    try:
        from tools.autopilot_state import build_autopilot_state

        resolved_repo_root = repo_root or _h().BASE_DIR
        resolved_memory_dir = memory_dir or str(default_memory_dir(resolved_repo_root))
        state = build_autopilot_state(
            resolved_repo_root,
            domain,
            memory_dir=resolved_memory_dir,
        )
    except Exception:
        return ""

    lines = []
    next_action = str(state.get("next_action", "") or "").strip()
    if next_action:
        lines.append(f"Next action hint: {next_action}")

    guard_hint = str(state.get("guard_hint", "") or "").strip()
    if guard_hint:
        lines.append(f"Guard hint: {guard_hint}")

    guard_status = state.get("guard_status") or {}
    tripped_hosts = [item for item in guard_status.get("tripped_hosts", []) if item.get("host")]
    if tripped_hosts:
        blocked = ", ".join(
            f"{item['host']} ({float(item.get('remaining_seconds', 0.0) or 0.0):.1f}s)"
            for item in tripped_hosts[:3]
        )
        lines.append(f"Avoid now: {blocked}")

    recent_guard_blocks = state.get("recent_guard_blocks", []) or []
    if recent_guard_blocks:
        lines.append("Recent guard blocks:")
        for item in recent_guard_blocks[:3]:
            details = str(item.get("notes", "") or item.get("endpoint", "") or "").strip()
            if details:
                lines.append(f"- {details}")

    resume_targets = [item for item in state.get("resume_targets", []) if item]
    if resume_targets:
        lines.append(f"Resume targets: {', '.join(resume_targets[:3])}")

    summary = state.get("resume_summary") or {}
    latest_session = summary.get("latest_session_summary") or {}
    vuln_classes = [item for item in latest_session.get("vuln_classes", []) if item]
    if vuln_classes:
        lines.append(f"Last vuln classes: {', '.join(vuln_classes[:4])}")
    if latest_session:
        lines.append(f"Last session findings: {int(latest_session.get('findings_count', 0) or 0)}")

    recommended_targets = state.get("recommended_targets", []) or []
    if recommended_targets:
        top = recommended_targets[0]
        top_url = str(top.get("url", "") or "").strip()
        top_suggested = str(top.get("suggested", "") or "").strip()
        if top.get("tripped"):
            cooldown = float(top.get("remaining_seconds", 0.0) or 0.0)
            if top_url:
                lines.append(f"Top ranked target cooling down: {top_url} ({cooldown:.1f}s)")
        elif top_url and top_suggested:
            lines.append(f"Top ready target: {top_url} ({top_suggested})")
        elif top_url:
            lines.append(f"Top ready target: {top_url}")

    if not lines:
        return ""

    return "## Resume / autopilot bootstrap\n" + "\n".join(f"- {line}" for line in lines)


def _session_summary_vuln_classes_from_agent(memory: HuntMemory) -> list[str]:
    """Derive minimal vuln-class / scan-mode labels from agent activity."""
    alias_map = {
        "run_recon": "recon",
        "run_vuln_scan": "vuln_scan",
        "run_sqlmap_on_file": "sqlmap",
        "run_sqlmap_targeted": "sqlmap",
        "run_cve_hunt": "cve",
        "run_zero_day_fuzzer": "zero_day",
    }
    ignored_steps = {
        "check_tools",
        "generate_reports",
        "finish",
        "read_autopilot_state",
        "read_findings_summary",
        "read_guard_status",
        "read_recon_summary",
        "read_repo_source_summary",
        "read_resume_summary",
        "read_surface_summary",
        "remember_finding",
        "run_intel",
        "update_working_memory",
    }

    classes: list[str] = []

    def _collect(label: str) -> None:
        if not label or label in ignored_steps:
            return
        if label.startswith("read_"):
            return
        if label in alias_map:
            classes.append(alias_map[label])
            return
        if label.startswith("run_"):
            classes.append(label.removeprefix("run_"))

    for step in dict.fromkeys(memory.completed_steps):
        _collect(str(step))

    if not classes:
        for finding in memory.findings_log:
            _collect(str(finding.get("tool", "")))

    return list(dict.fromkeys(classes))


def _session_summary_profile_endpoints(profile: dict[str, Any]) -> list[str]:
    """Resolve tested endpoints from target profile with findings fallback."""
    endpoints = []
    if isinstance(profile, dict):
        endpoints.extend(str(item).strip() for item in profile.get("tested_endpoints", []) if str(item).strip())
        if not endpoints:
            for finding in profile.get("findings", []):
                endpoint = str(finding.get("endpoint", "")).strip()
                if endpoint:
                    endpoints.append(endpoint)
    return list(dict.fromkeys(endpoints))


def _session_summary_vuln_classes_from_profile(profile: dict[str, Any]) -> list[str]:
    """Resolve remembered vuln classes from persisted target profile findings."""
    classes = []
    if isinstance(profile, dict):
        for finding in profile.get("findings", []):
            vuln_class = str(finding.get("vuln_class", "")).strip().lower()
            if vuln_class:
                classes.append(vuln_class)
    return list(dict.fromkeys(classes))


def _auto_log_agent_session_summary(domain: str, memory: HuntMemory, session_id: str | None) -> None:
    """Auto-log a non-fatal session summary for agent-driven runs."""
    try:
        memory_dir = default_memory_dir(_h().BASE_DIR)
        profile = load_target_profile(memory_dir, domain) or {}
        endpoints_tested = _session_summary_profile_endpoints(profile)
        remembered_findings = profile.get("findings", []) if isinstance(profile, dict) else []
        vuln_classes = list(
            dict.fromkeys(
                _session_summary_vuln_classes_from_agent(memory)
                + _session_summary_vuln_classes_from_profile(profile)
            )
        )
        journal = HuntJournal(Path(memory_dir) / "journal.jsonl")
        journal.log_session_summary(
            target=domain,
            action="hunt",
            endpoints_tested=endpoints_tested,
            vuln_classes_tried=vuln_classes,
            findings_count=max(len(memory.findings_log), len(remembered_findings)),
            session_id=session_id,
        )
    except Exception as exc:
        print(f"{YELLOW}[Agent] Auto session memory failed (non-fatal): {exc}{NC}", flush=True)


# ──────────────────────────────────────────────────────────────────────────────
#  Public entry point  (called by tools/hunt.py --agent)
# ──────────────────────────────────────────────────────────────────────────────

def run_agent_hunt(
    domain: str,
    *,
    scope_lock: bool = False,
    max_urls: int = 100,
    max_steps: int = 20,
    time_budget_hours: float = 2.0,
    cookies: str = "",
    model: str | None = None,
    resume_session_id: str | None = None,
    use_langgraph: bool = False,
    ctf_mode: bool | None = None,
    autopilot_mode: str = "paranoid",
) -> dict:
    """
    Main entry point for agent-driven autonomous hunting.
    Called by tools/hunt.py when --agent flag is passed.
    """
    h = _h()
    ctf_mode = _resolve_ctf_mode(ctf_mode)
    autopilot_mode = _normalize_autopilot_mode(autopilot_mode)

    # ── Resolve session ───────────────────────────────────────────────────
    session_id, recon_dir = h._activate_recon_session(
        domain,
        requested_session_id=resume_session_id or "latest",
        create=True,
    )
    session_dir  = os.path.dirname(recon_dir)
    session_file = os.path.join(session_dir, "agent_session.json")

    print(f"{GREEN}[Agent] Session: {session_id} → {recon_dir}{NC}", flush=True)
    print(f"{DIM}[Agent] Checkpoint mode: {autopilot_mode}{NC}", flush=True)
    if ctf_mode:
        print(f"{YELLOW}[Agent] CTF mode enabled — treating provided target as local practice scope.{NC}", flush=True)

    # ── Init memory + dispatcher ──────────────────────────────────────────
    memory     = HuntMemory(session_file)
    base_dir = getattr(h, "BASE_DIR", os.getcwd())
    memory.bootstrap_context = _build_agent_bootstrap_context(
        domain,
        repo_root=base_dir,
        memory_dir=str(default_memory_dir(base_dir)),
    )
    dispatcher = ToolDispatcher(
        domain, memory,
        scope_lock=scope_lock,
        max_urls=max_urls,
        default_cookies=cookies,
    )

    # ── Run ───────────────────────────────────────────────────────────────
    if use_langgraph and _LANGGRAPH_OK:
        print(f"{GREEN}[Agent] Using real LangGraph backend.{NC}", flush=True)
        picked_model = model or (_pick_model() if _BRAIN_OK else None) or "qwen2.5:32b"
        try:
            graph   = build_langgraph_agent(
                domain,
                dispatcher,
                memory,
                picked_model,
                max_steps,
                ctf_mode=ctf_mode,
                autopilot_mode=autopilot_mode,
            )
            initial = {"messages": [HumanMessage(content=f"Hunt {domain}. Begin.")]}
            result_state = graph.invoke(initial, config={"recursion_limit": max_steps * 2})
            _auto_log_agent_session_summary(domain, memory, session_id)
            return {
                "domain":          domain,
                "success":         True,
                "model":           picked_model,
                "backend":         "langgraph",
                "ctf_mode":        ctf_mode,
                "autopilot_mode":  autopilot_mode,
                "steps":           memory.step_count,
                "completed_steps": list(dict.fromkeys(memory.completed_steps)),
                "reports":         len(memory.findings_log),
                "findings":        len(memory.findings_log),
                "session_file":    session_file,
                "working_memory":  memory.working_memory,
                **_phase_flags(memory.completed_steps),
            }
        except Exception as e:
            print(f"{YELLOW}[Agent] LangGraph error: {e} — falling back to built-in{NC}",
                  flush=True)

    # Built-in ReAct loop
    log_path  = os.path.join(session_dir, "agent_trace.jsonl")
    bump_path = os.path.join(session_dir, "agent_bump.txt")
    tracer    = AgentTracer(log_path)

    print(f"{GREEN}[Agent] Trace: tail -f {log_path}{NC}", flush=True)
    print(f"{GREEN}[Agent] Bump:  echo 'guidance here' > {bump_path}{NC}", flush=True)

    agent = ReActAgent(
        domain      = domain,
        memory      = memory,
        dispatcher  = dispatcher,
        max_steps   = max_steps,
        time_budget_hours = time_budget_hours,
        model       = model,
        tracer      = tracer,
        ctf_mode    = ctf_mode,
        autopilot_mode = autopilot_mode,
    )
    agent.bump_file = bump_path

    result = agent.run()
    tracer.close()
    _auto_log_agent_session_summary(domain, memory, session_id)
    result["backend"]    = "builtin-react"
    result["trace_path"] = log_path
    result["bump_path"]  = bump_path
    result["ctf_mode"]   = ctf_mode
    result["autopilot_mode"] = autopilot_mode
    return result


# ──────────────────────────────────────────────────────────────────────────────
#  CLI
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="ReAct hunting agent — autonomous bug bounty with Ollama tool calling",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 agent.py --target example.com
  python3 agent.py --target example.com --time 4 --max-steps 30
  python3 agent.py --target example.com --cookie "JSESSIONID=abc123"
  python3 agent.py --target example.com --scope-lock --max-urls 50
  python3 agent.py --target example.com --langgraph
  python3 agent.py --target example.com --resume SESSION_ID
  python3 agent.py --list-models
"""
    )
    parser.add_argument("--target",      required=False, help="Domain to hunt")
    parser.add_argument("--time",        type=float, default=2.0, help="Time budget in hours (default 2)")
    parser.add_argument("--max-steps",   type=int,   default=20,  help="Max ReAct iterations (default 20)")
    parser.add_argument("--cookie",      type=str,   default="",  help="Session cookie for POST discovery")
    parser.add_argument("--scope-lock",  action="store_true",     help="Stick to exact target only")
    parser.add_argument("--max-urls",    type=int,   default=100, help="Max URLs in recon (default 100)")
    parser.add_argument("--model",       type=str,   default=None, help="Ollama model override")
    parser.add_argument("--langgraph",   action="store_true",     help="Use real LangGraph backend")
    parser.add_argument("--resume",      type=str,   default=None, help="Resume session ID")
    parser.add_argument("--list-models", action="store_true",     help="List available Ollama models")
    parser.add_argument("--bump",        type=str,   default=None,
                        help="Inject operator guidance mid-run: --bump SESSION_DIR 'message'",
                        nargs=2, metavar=("SESSION_DIR", "MESSAGE"))
    args = parser.parse_args()

    if args.list_models:
        if not _OLLAMA_OK:
            print("Ollama not installed: pip install ollama")
            return
        client = _ollama_lib.Client(host=OLLAMA_HOST)
        try:
            models = [m.model for m in client.list().models]
            print(f"\nAvailable Ollama models ({len(models)}):")
            for m in models:
                marker = " ← recommended" if any(m.startswith(p.split(":")[0]) for p in
                         ["qwen3-coder", "qwen2.5", "qwen3"]) else ""
                print(f"  {m}{marker}")
        except Exception as e:
            print(f"Cannot reach Ollama: {e}")
        print(f"\nLangGraph available: {_LANGGRAPH_OK}")
        print(f"Ollama available:    {_OLLAMA_OK}")
        return

    if args.bump:
        session_dir, message = args.bump
        bump_file = os.path.join(session_dir, "agent_bump.txt")
        Path(bump_file).write_text(message.strip())
        print(f"[Bump] Wrote guidance to {bump_file}")
        print(f"[Bump] Agent will pick it up on next step.")
        return

    if not args.target:
        parser.print_help()
        sys.exit(1)

    try:
        result = run_agent_hunt(
            args.target,
            scope_lock=args.scope_lock,
            max_urls=args.max_urls,
            max_steps=args.max_steps,
            time_budget_hours=args.time,
            cookies=args.cookie,
            model=args.model,
            resume_session_id=args.resume,
            use_langgraph=args.langgraph,
        )
    except RuntimeError as exc:
        print(f"{RED}[Agent] {exc}{NC}")
        sys.exit(1)

    print(f"\n{BOLD}{'═'*60}{NC}")
    print(f"{BOLD}Hunt Result: {result['domain']}{NC}")
    print(f"  Backend:   {result.get('backend', 'unknown')}")
    print(f"  Model:     {result.get('model', 'unknown')}")
    print(f"  Steps:     {result.get('steps', 0)}")
    print(f"  Findings:  {result.get('findings', 0)}")
    print(f"  Session:   {result.get('session_file', '')}")
    if result.get("trace_path"):
        print(f"  Trace:     {result['trace_path']}")
    if result.get("bump_path"):
        print(f"  Bump:      echo 'guidance' > {result['bump_path']}")
    if result.get("verdict"):
        print(f"\nVerdict:\n{result['verdict']}")
    print(f"{BOLD}{'═'*60}{NC}\n")


if __name__ == "__main__":
    main()
