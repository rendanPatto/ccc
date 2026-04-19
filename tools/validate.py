#!/usr/bin/env python3
"""
validate.py — Interactive bug validation assistant.
Walks through the 4 validation gates, checks for duplicates, calculates CVSS,
and generates a skeleton HackerOne report.

Usage:
  python3 tools/validate.py
  python3 tools/validate.py --output findings/myreport.md
"""

import argparse
import json
import os
import ssl
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent.parent

# macOS: Python may not have system SSL certs. Use unverified context for API queries.
_SSL_CTX = ssl.create_default_context()
try:
    import certifi
    _SSL_CTX = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    _SSL_CTX.check_hostname = False
    _SSL_CTX.verify_mode = ssl.CERT_NONE

# ─── Color codes ──────────────────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

# ─── CVSS 4.0 scoring ─────────────────────────────────────────────────────────

CVSS4_WEIGHTS = {
    "AV": {"N": 1.00, "A": 0.80, "L": 0.50, "P": 0.20},
    "AC": {"L": 1.00, "H": 0.70},
    "AT": {"N": 1.00, "P": 0.85},
    "PR": {"N": 1.00, "L": 0.75, "H": 0.45},
    "UI": {"N": 1.00, "P": 0.80, "A": 0.55},
    "VC": {"H": 1.00, "L": 0.45, "N": 0.00},
    "VI": {"H": 1.00, "L": 0.45, "N": 0.00},
    "VA": {"H": 1.00, "L": 0.45, "N": 0.00},
    "SC": {"H": 1.00, "L": 0.45, "N": 0.00},
    "SI": {"H": 1.00, "L": 0.45, "N": 0.00},
    "SA": {"H": 1.00, "L": 0.45, "N": 0.00},
}


def calculate_cvss4(av, ac, at, pr, ui, vc, vi, va, sc, si, sa) -> tuple[float, str]:
    """Calculate a CVSS 4.0-style base score and return (score, vector_string)."""
    exploitability = (
        CVSS4_WEIGHTS["AV"][av]
        * CVSS4_WEIGHTS["AC"][ac]
        * CVSS4_WEIGHTS["AT"][at]
        * CVSS4_WEIGHTS["PR"][pr]
        * CVSS4_WEIGHTS["UI"][ui]
    )
    vulnerable_system_impact = (
        CVSS4_WEIGHTS["VC"][vc]
        + CVSS4_WEIGHTS["VI"][vi]
        + CVSS4_WEIGHTS["VA"][va]
    ) / 3
    subsequent_system_impact = (
        CVSS4_WEIGHTS["SC"][sc]
        + CVSS4_WEIGHTS["SI"][si]
        + CVSS4_WEIGHTS["SA"][sa]
    ) / 3
    impact = (vulnerable_system_impact * 0.7) + (subsequent_system_impact * 0.3)

    if impact <= 0:
        score = 0.0
    else:
        score = round(min(10.0, 10 * exploitability * impact), 1)

    vector = (
        f"CVSS:4.0/AV:{av}/AC:{ac}/AT:{at}/PR:{pr}/UI:{ui}/"
        f"VC:{vc}/VI:{vi}/VA:{va}/SC:{sc}/SI:{si}/SA:{sa}"
    )
    return score, vector


def calculate_cvss(av, ac, pr, ui, s, c, i, a) -> tuple[float, str]:
    """Backward-compatible alias that maps legacy calls onto the CVSS 4.0 scorer."""
    del s
    return calculate_cvss4(av, ac, "N", pr, ui, c, i, a, "N", "N", "N")


def severity_from_score(score: float) -> str:
    if score == 0.0:  return "NONE"
    if score < 4.0:   return "LOW"
    if score < 7.0:   return "MEDIUM"
    if score < 9.0:   return "HIGH"
    return "CRITICAL"


def load_config() -> dict:
    """Load optional repo config.json. Missing or invalid config is ignored."""
    config_path = Path(__file__).resolve().parent.parent / "config.json"
    if not config_path.exists():
        return {}

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


# ─── HackerOne dup check ──────────────────────────────────────────────────────

def check_h1_dups(program_handle: str, vuln_keyword: str) -> list[dict]:
    """Search HackerOne for potential duplicates."""
    if not program_handle:
        return []

    query = {
        "query": f"""{{
          hacktivity_items(
            first: 10,
            order_by: {{ field: popular, direction: DESC }},
            where: {{
              team: {{ handle: {{ _eq: "{program_handle}" }} }},
              report: {{ title: {{ _icontains: "{vuln_keyword}" }} }}
            }}
          ) {{
            nodes {{
              ... on HacktivityDocument {{
                report {{
                  title
                  severity_rating
                  disclosed_at
                  url
                  state
                }}
              }}
            }}
          }}
        }}"""
    }
    try:
        req = urllib.request.Request(
            "https://hackerone.com/graphql",
            data=json.dumps(query).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10, context=_SSL_CTX) as resp:
            data = json.loads(resp.read().decode())
        nodes = (data.get("data") or {}).get("hacktivity_items", {}).get("nodes", [])
        results = []
        for node in nodes:
            r = node.get("report")
            if r:
                results.append(r)
        return results
    except Exception:
        return []


# ─── Interactive prompt helpers ───────────────────────────────────────────────

def ask(prompt: str, default: str = "") -> str:
    if default:
        val = input(f"  {prompt} [{default}]: ").strip()
        return val if val else default
    return input(f"  {prompt}: ").strip()


def ask_yn(prompt: str, default: bool = True) -> bool:
    yn = "Y/n" if default else "y/N"
    val = input(f"  {prompt} [{yn}]: ").strip().lower()
    if not val:
        return default
    return val in ("y", "yes")


def ask_choice(prompt: str, choices: list[tuple[str, str]]) -> str:
    """Ask user to pick from labeled choices. Returns the choice key."""
    print(f"\n  {prompt}")
    for key, label in choices:
        print(f"    {CYAN}{key}{RESET}) {label}")
    while True:
        val = input(f"  Choice: ").strip().upper()
        if val in [k for k, _ in choices]:
            return val
        print(f"  {YELLOW}Invalid — enter one of: {', '.join(k for k,_ in choices)}{RESET}")


def section(title: str):
    print(f"\n{BOLD}{BLUE}{'─' * 60}{RESET}")
    print(f"{BOLD}{BLUE}  {title}{RESET}")
    print(f"{BOLD}{BLUE}{'─' * 60}{RESET}\n")


def gate_header(n: int, name: str, status: str | None = None):
    status_str = ""
    if status == "PASS":
        status_str = f" {GREEN}✓ PASS{RESET}"
    elif status == "FAIL":
        status_str = f" {RED}✗ FAIL{RESET}"
    print(f"\n{BOLD}Gate {n}: {name}{RESET}{status_str}")
    print(f"{'─' * 40}")


# ─── Gate implementations ─────────────────────────────────────────────────────

def gate1_is_real() -> tuple[bool, dict]:
    gate_header(1, "Is It Real?")
    print("  Can you reproduce the bug from scratch — clean browser, no Burp artifacts?")
    print()
    repro3   = ask_yn("Reproduced 3/3 times deterministically?")
    no_burp  = ask_yn("Works with plain curl or fresh browser (not just in Burp)?")
    no_state = ask_yn("No unusual preconditions (doesn't require specific timing or race)?")
    rtfm     = ask_yn("Checked documentation — this isn't expected/documented behavior?")

    passed = repro3 and no_burp and no_state and rtfm
    notes = {
        "repro_3_3": repro3,
        "works_without_proxy": no_burp,
        "no_special_state": no_state,
        "not_documented_behavior": rtfm,
    }

    if not passed:
        print(f"\n  {RED}GATE 1 FAIL: Not reliably reproducible.{RESET}")
        print(f"  {DIM}Do not submit yet. Verify the bug is deterministic first.{RESET}")
    else:
        print(f"\n  {GREEN}GATE 1 PASS{RESET}")

    return passed, notes


def gate2_in_scope(program_handle: str, skip_scope: bool = False) -> tuple[bool, dict]:
    gate_header(2, "Is It In Scope?")
    if skip_scope:
        print("  CTF mode enabled — skipping program scope validation.")
        print(f"\n  {GREEN}GATE 2 PASS (SKIPPED IN CTF MODE){RESET}")
        return True, {
            "asset_in_scope": True,
            "not_excluded": True,
            "version_ok": True,
            "skipped_in_ctf_mode": True,
        }

    print("  Check the program scope page explicitly — don't assume.")
    print()

    asset_in_scope  = ask_yn("The affected domain/asset is listed on the program's scope page?")
    not_excluded    = ask_yn("Not in the out-of-scope list (check staging, third-party exclusions)?")
    version_ok      = ask_yn("Affected software version is in scope (not an excluded old version)?")

    if program_handle:
        print(f"\n  {DIM}Checking HackerOne scope for '{program_handle}'...{RESET}")
        try:
            query = {
                "query": f'{{ team(handle: "{program_handle}") {{ policy_scopes(archived: false) {{ edges {{ node {{ asset_type asset_identifier eligible_for_bounty }} }} }} }} }}'
            }
            req = urllib.request.Request(
                "https://hackerone.com/graphql",
                data=json.dumps(query).encode(),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=8, context=_SSL_CTX) as resp:
                data = json.loads(resp.read().decode())
            scopes = (data.get("data") or {}).get("team", {}).get("policy_scopes", {}).get("edges", [])
            if scopes:
                print(f"\n  {CYAN}In-scope assets for {program_handle}:{RESET}")
                for edge in scopes[:10]:
                    node = edge.get("node", {})
                    bounty = " (eligible)" if node.get("eligible_for_bounty") else ""
                    print(f"    • [{node.get('asset_type','?')}] {node.get('asset_identifier','?')}{bounty}")
        except Exception:
            print(f"  {YELLOW}Could not fetch scope (network error){RESET}")

    passed = asset_in_scope and not_excluded and version_ok
    notes = {
        "asset_in_scope": asset_in_scope,
        "not_excluded": not_excluded,
        "version_ok": version_ok,
    }

    if not passed:
        print(f"\n  {RED}GATE 2 FAIL: May be out of scope.{RESET}")
        print(f"  {DIM}Confirm scope before submitting.{RESET}")
    else:
        print(f"\n  {GREEN}GATE 2 PASS{RESET}")

    return passed, notes


def gate3_exploitable() -> tuple[bool, dict]:
    gate_header(3, "Is It Exploitable?")
    print("  Can you demonstrate concrete impact without unrealistic preconditions?")
    print()

    concrete_impact  = ask_yn("Can you show concrete impact (not just 'theoretically an attacker could')?")
    no_unrealistic   = ask_yn("No unrealistic preconditions (not 'must be admin already', not 'victim must run JS')?")
    can_demonstrate  = ask_yn("Have proof you can show a triager (screenshot, curl, PoC)?")

    print()
    print("  What is the concrete impact? (be specific)")
    impact_desc = ask("Describe the impact")

    passed = concrete_impact and no_unrealistic and can_demonstrate
    notes = {
        "concrete_impact": concrete_impact,
        "no_unrealistic_preconditions": no_unrealistic,
        "has_proof": can_demonstrate,
        "impact_description": impact_desc,
    }

    if not passed:
        print(f"\n  {RED}GATE 3 FAIL: Exploitability not demonstrated.{RESET}")
        print(f"  {DIM}Build a working PoC before submitting.{RESET}")
    else:
        print(f"\n  {GREEN}GATE 3 PASS{RESET}")

    return passed, notes


def gate4_not_dup(vuln_type: str, endpoint: str, program_handle: str) -> tuple[bool, dict]:
    gate_header(4, "Is It a Dup?")
    print("  Check HackerOne disclosed reports, GitHub issues, and recent changelog.")
    print()

    # Auto-check HackerOne
    h1_results = []
    if program_handle and vuln_type:
        print(f"  {DIM}Searching HackerOne for '{vuln_type}' in '{program_handle}'...{RESET}")
        h1_results = check_h1_dups(program_handle, vuln_type)
        if h1_results:
            print(f"\n  {YELLOW}Found {len(h1_results)} potentially similar disclosed reports:{RESET}")
            for r in h1_results:
                disclosed = (r.get("disclosed_at") or "")[:10]
                print(f"    • [{r.get('severity_rating','?').upper()}] {r.get('title','')} ({disclosed})")
                if r.get("url"):
                    print(f"      {DIM}{r['url']}{RESET}")
        else:
            print(f"  {GREEN}No similar disclosed reports found on HackerOne.{RESET}")

    print()
    not_disclosed   = ask_yn("Not found in HackerOne disclosed reports for this program?")
    not_in_issues   = ask_yn("Not already fixed/reported in GitHub issues or CHANGELOG?")
    checked_history = ask_yn("Checked git log for recent security fixes with this pattern?")

    passed = not_disclosed and not_in_issues and checked_history
    notes = {
        "not_in_h1_disclosed": not_disclosed,
        "not_in_github_issues": not_in_issues,
        "checked_git_history": checked_history,
        "h1_similar_reports": [r.get("title") for r in h1_results],
    }

    if not passed:
        print(f"\n  {RED}GATE 4 FAIL: Possible duplicate.{RESET}")
        print(f"  {DIM}Verify it's not already known before submitting.{RESET}")
    else:
        print(f"\n  {GREEN}GATE 4 PASS{RESET}")

    return passed, notes


# ─── CVSS interactive scorer ──────────────────────────────────────────────────

def ask_cvss_score() -> tuple[float, str, dict]:
    section("CVSS 4.0 Scoring")

    av = ask_choice("Attack Vector (AV)", [
        ("N", "Network — exploitable remotely over internet"),
        ("A", "Adjacent — requires same network segment"),
        ("L", "Local — requires local access to system"),
        ("P", "Physical — requires physical device access"),
    ])
    ac = ask_choice("Attack Complexity (AC)", [
        ("L", "Low — reliable, no special conditions"),
        ("H", "High — requires specific conditions or timing"),
    ])
    at = ask_choice("Attack Requirements (AT)", [
        ("N", "None — no extra deployment/runtime condition required"),
        ("P", "Present — exploit depends on a specific condition being true"),
    ])
    pr = ask_choice("Privileges Required (PR)", [
        ("N", "None — no account needed"),
        ("L", "Low — regular user account"),
        ("H", "High — admin / elevated privileges"),
    ])
    ui = ask_choice("User Interaction (UI)", [
        ("N", "None — no user interaction required"),
        ("P", "Passive — user is exposed during normal use"),
        ("A", "Active — user must perform a specific action"),
    ])
    vc = ask_choice("Vulnerable System Confidentiality (VC)", [
        ("H", "High — complete disclosure of vulnerable system data"),
        ("L", "Low — partial disclosure of vulnerable system data"),
        ("N", "None"),
    ])
    vi = ask_choice("Vulnerable System Integrity (VI)", [
        ("H", "High — complete modification of vulnerable system data"),
        ("L", "Low — limited modification of vulnerable system data"),
        ("N", "None"),
    ])
    va = ask_choice("Vulnerable System Availability (VA)", [
        ("H", "High — complete shutdown or major service loss"),
        ("L", "Low — reduced performance or intermittent disruption"),
        ("N", "None"),
    ])
    sc = ask_choice("Subsequent System Confidentiality (SC)", [
        ("H", "High — complete disclosure in a subsequent system"),
        ("L", "Low — partial disclosure in a subsequent system"),
        ("N", "None"),
    ])
    si = ask_choice("Subsequent System Integrity (SI)", [
        ("H", "High — complete modification in a subsequent system"),
        ("L", "Low — limited modification in a subsequent system"),
        ("N", "None"),
    ])
    sa = ask_choice("Subsequent System Availability (SA)", [
        ("H", "High — complete disruption in a subsequent system"),
        ("L", "Low — partial disruption in a subsequent system"),
        ("N", "None"),
    ])

    score, vector = calculate_cvss4(av, ac, at, pr, ui, vc, vi, va, sc, si, sa)
    sev = severity_from_score(score)

    sev_color = RED if sev in ("CRITICAL", "HIGH") else (YELLOW if sev == "MEDIUM" else GREEN)
    print(f"\n  {BOLD}CVSS 4.0 Score: {sev_color}{score} {sev}{RESET}")
    print(f"  {BOLD}Vector:{RESET} {vector}")

    params = {
        "AV": av, "AC": ac, "AT": at, "PR": pr, "UI": ui,
        "VC": vc, "VI": vi, "VA": va, "SC": sc, "SI": si, "SA": sa,
    }
    return score, vector, params


def score_cvss() -> tuple[float, str, dict]:
    """Backward-compatible alias for the interactive CVSS 4.0 scorer."""
    return ask_cvss_score()


# ─── Report skeleton generator ────────────────────────────────────────────────

def generate_report_skeleton(info: dict) -> str:
    """Generate a HackerOne-style report skeleton."""
    vuln_type  = info.get("vuln_type", "VULN_TYPE")
    target     = info.get("target", "TARGET")
    endpoint   = info.get("endpoint", "ENDPOINT")
    impact     = info.get("impact", "IMPACT_DESCRIPTION")
    score      = info.get("cvss_score", 0.0)
    vector     = info.get("cvss_vector", "CVSS:4.0/...")
    sev        = severity_from_score(score)
    date       = datetime.now().strftime("%Y-%m-%d")

    return f"""# {vuln_type} on {endpoint} — [fill in specific impact]

**Program:** {target}
**Severity:** {sev} ({score}) — {vector}
**Date Found:** {date}

---

## Summary

[2-3 sentences. What is the vulnerability? Where is it? What can an attacker do?]

The `{endpoint}` endpoint [describe the vulnerability in one sentence]. By [describe
the attack], an attacker can [describe the concrete impact].

---

## Steps to Reproduce

> **Setup:** Create two accounts — Attacker (email: attacker@test.com) and Victim (email: victim@test.com).

1. Log in as **Attacker**
2. [Step 2 — specific action]
3. [Step 3 — specific request with actual parameter names]
   ```
   [INSERT ACTUAL HTTP REQUEST HERE — e.g., curl command or Burp request]
   ```
4. [Step 4 — what to observe in the response]
5. Confirm: [what proves the vulnerability — e.g., victim's data appears in response]

---

## Proof of Concept

**Request:**
```http
[PASTE ACTUAL REQUEST — METHOD, URL, HEADERS, BODY]
```

**Response:**
```json
[PASTE ACTUAL RESPONSE SHOWING THE VULNERABILITY]
```

**Screenshots:** [attach: TARGET-{vuln_type.lower().replace(' ','-')}-step1.png, etc.]

---

## Impact

{impact}

[Quantify: number of users affected, type of data exposed, what actions an attacker can take]

---

## CVSS 4.0

**Vector:** `{vector}`
**Score:** {score} ({sev})

| Metric | Value | Rationale |
|---|---|---|
| Attack Vector | {info.get('cvss_params', {}).get('AV', '?')} | [explain] |
| Attack Complexity | {info.get('cvss_params', {}).get('AC', '?')} | [explain] |
| Attack Requirements | {info.get('cvss_params', {}).get('AT', '?')} | [explain] |
| Privileges Required | {info.get('cvss_params', {}).get('PR', '?')} | [explain] |
| User Interaction | {info.get('cvss_params', {}).get('UI', '?')} | [explain] |
| Vulnerable System Confidentiality | {info.get('cvss_params', {}).get('VC', '?')} | [explain] |
| Vulnerable System Integrity | {info.get('cvss_params', {}).get('VI', '?')} | [explain] |
| Vulnerable System Availability | {info.get('cvss_params', {}).get('VA', '?')} | [explain] |
| Subsequent System Confidentiality | {info.get('cvss_params', {}).get('SC', '?')} | [explain] |
| Subsequent System Integrity | {info.get('cvss_params', {}).get('SI', '?')} | [explain] |
| Subsequent System Availability | {info.get('cvss_params', {}).get('SA', '?')} | [explain] |

---

## Fix Recommendation

[Specific code-level fix — name the file, function, and what to change]

Example: In `path/to/file.ts`, the `functionName` function should verify
`resource.user_id === req.user.id` before returning data.

---

## Validation Notes

| Gate | Result |
|---|---|
| Is it real? | {'PASS' if info.get('gate1_pass') else 'FAIL'} |
| Is it in scope? | {'PASS' if info.get('gate2_pass') else 'FAIL'} |
| Is it exploitable? | {'PASS' if info.get('gate3_pass') else 'FAIL'} |
| Is it a dup? | {'PASS' if info.get('gate4_pass') else 'FAIL'} |
"""


def derive_validate_target(program_handle: str, endpoint: str) -> str:
    """Prefer endpoint host when available, otherwise fall back to program handle."""
    raw_endpoint = (endpoint or "").strip()
    if raw_endpoint.startswith(("http://", "https://")):
        parsed = urlparse(raw_endpoint)
        if parsed.netloc:
            return parsed.netloc.lower()
    return (program_handle or "unknown").strip()


def build_validation_summary(info: dict, *, all_pass: bool, report_path: str | Path) -> dict:
    """Build a compact JSON summary that /remember can import later."""
    vuln_class = (info.get("vuln_type") or "").strip().lower()
    severity = severity_from_score(float(info.get("cvss_score", 0.0) or 0.0)).lower()
    return {
        "target": derive_validate_target(info.get("target", ""), info.get("endpoint", "")),
        "program": (info.get("target") or "").strip(),
        "endpoint": (info.get("endpoint") or "").strip(),
        "vuln_class": vuln_class,
        "result": "confirmed" if all_pass else "partial",
        "severity": severity,
        "notes": (info.get("impact") or "").strip(),
        "impact": (info.get("impact") or "").strip(),
        "cvss_score": float(info.get("cvss_score", 0.0) or 0.0),
        "cvss_vector": info.get("cvss_vector", ""),
        "all_gates_passed": bool(all_pass),
        "report_path": str(report_path),
        "validated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def write_validation_summary(summary: dict, report_path: str | Path) -> None:
    """Persist per-report summary and repo-global last-validate pointer."""
    report_path = Path(report_path)
    report_summary_path = report_path.parent / "validation-summary.json"
    report_summary_path.parent.mkdir(parents=True, exist_ok=True)
    report_summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    last_validate_path = BASE_DIR / "findings" / "last-validate.json"
    last_validate_path.parent.mkdir(parents=True, exist_ok=True)
    last_validate_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Interactive bug validation assistant")
    parser.add_argument("--output",  default="", help="Output path for generated report skeleton")
    parser.add_argument("--program", default="", help="HackerOne program handle for dup check")
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}{'═' * 60}{RESET}")
    print(f"{BOLD}{CYAN}  Bug Bounty Validation Assistant{RESET}")
    print(f"{BOLD}{CYAN}{'═' * 60}{RESET}")
    print(f"\nThis will walk you through the 4 validation gates,")
    print(f"calculate your CVSS score, and generate a report skeleton.\n")

    config = load_config()
    ctf_mode = bool(config.get("ctf_mode", False))
    if ctf_mode:
        print(f"{YELLOW}CTF mode enabled:{RESET} scope validation is skipped in Gate 2.\n")

    # Collect basic info upfront
    section("Target Information")
    target_program = args.program or ask("HackerOne program handle (e.g., 'target-program')", "unknown")
    vuln_type      = ask("Vulnerability type (e.g., 'IDOR', 'Stored XSS', 'SSRF')")
    endpoint       = ask("Affected endpoint (e.g., '/api/invoices/:id')")

    # Run the 4 gates
    g1_pass, g1_notes = gate1_is_real()
    g2_pass, g2_notes = gate2_in_scope(target_program, skip_scope=ctf_mode)
    g3_pass, g3_notes = gate3_exploitable()
    g4_pass, g4_notes = gate4_not_dup(vuln_type, endpoint, target_program)

    # Summary
    section("Validation Summary")
    gates = [
        (1, "Is it real?",       g1_pass),
        (2, "Is it in scope?",   g2_pass),
        (3, "Is it exploitable?",g3_pass),
        (4, "Is it a dup?",      g4_pass),
    ]
    all_pass = all(p for _, _, p in gates)

    for n, name, passed in gates:
        icon = f"{GREEN}✓{RESET}" if passed else f"{RED}✗{RESET}"
        print(f"  Gate {n} — {name}: {icon}")

    print()
    if all_pass:
        print(f"  {BOLD}{GREEN}All gates passed! This looks like a valid finding.{RESET}")
    else:
        failed = [name for _, name, p in gates if not p]
        print(f"  {BOLD}{RED}Failed: {', '.join(failed)}{RESET}")
        print(f"  {DIM}Resolve the failed gates before submitting.{RESET}")

    if not all_pass:
        if not ask_yn("\nContinue to CVSS scoring anyway?", default=False):
            sys.exit(0)

    # CVSS scoring
    cvss_score, cvss_vector, cvss_params = ask_cvss_score()

    # Generate report skeleton
    section("Report Generation")
    impact_desc = g3_notes.get("impact_description", "")

    info = {
        "target":      target_program,
        "vuln_type":   vuln_type,
        "endpoint":    endpoint,
        "impact":      impact_desc,
        "cvss_score":  cvss_score,
        "cvss_vector": cvss_vector,
        "cvss_params": cvss_params,
        "gate1_pass":  g1_pass,
        "gate2_pass":  g2_pass,
        "gate3_pass":  g3_pass,
        "gate4_pass":  g4_pass,
    }

    skeleton = generate_report_skeleton(info)

    # Determine output path
    if args.output:
        output_path = args.output
    else:
        safe_name = vuln_type.lower().replace(" ", "-").replace("/", "-")
        safe_target = target_program.replace(" ", "-")
        base_dir = os.path.join(
            str(BASE_DIR),
            "findings", f"{safe_target}-{safe_name}"
        )
        os.makedirs(base_dir, exist_ok=True)
        output_path = os.path.join(base_dir, "hackerone-report.md")

    with open(output_path, "w") as f:
        f.write(skeleton)

    summary = build_validation_summary(info, all_pass=all_pass, report_path=output_path)
    write_validation_summary(summary, output_path)

    print(f"  {BOLD}{GREEN}Report skeleton generated:{RESET} {output_path}")
    print(f"\n  {BOLD}Next steps:{RESET}")
    print(f"    1. Fill in the actual HTTP request + response in the PoC section")
    print(f"    2. Attach screenshots (naming: TARGET-VULN-TYPE-STEP-N.png)")
    print(f"    3. Replace all [bracketed] placeholders with specific details")
    print(f"    4. Run /bug-bounty-report for the submission checklist")
    print()


if __name__ == "__main__":
    main()
