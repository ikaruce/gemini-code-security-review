"""Security audit prompt templates for Gemini Code Security Review."""

from typing import Any, Dict, Optional


def get_security_audit_prompt(
    pr_data: Dict[str, Any],
    pr_diff: Optional[str] = None,
    include_diff: bool = True,
    custom_scan_instructions: Optional[str] = None,
) -> str:
    """Generate a comprehensive security audit prompt for Gemini.

    Args:
        pr_data: PR data dictionary from GitHub API
        pr_diff: Optional complete PR diff in unified format
        include_diff: Whether to include the diff in the prompt
        custom_scan_instructions: Optional custom security categories to append

    Returns:
        Complete security audit prompt string
    """
    pr_number = pr_data.get("number", "unknown")
    pr_title = pr_data.get("title", "")
    pr_body = pr_data.get("body", "") or ""
    pr_url = pr_data.get("html_url", "")

    base_url = pr_data.get("base", {})
    base_branch = base_url.get("ref", "main") if isinstance(base_url, dict) else "main"

    changed_files = pr_data.get("changed_files", "unknown")
    additions = pr_data.get("additions", "unknown")
    deletions = pr_data.get("deletions", "unknown")

    diff_section = ""
    if include_diff and pr_diff:
        diff_section = f"""
PR DIFF (unified format):
```diff
{pr_diff[:800_000]}
```
"""
    elif not include_diff:
        diff_section = "\n[Diff omitted due to size constraints — analyze repository files directly]\n"

    custom_section = ""
    if custom_scan_instructions:
        custom_section = f"""
ADDITIONAL SECURITY CATEGORIES TO EXAMINE:
{custom_scan_instructions}
"""

    return f"""You are a senior security engineer conducting a focused security review of a GitHub Pull Request.

PULL REQUEST INFORMATION:
- PR #: {pr_number}
- Title: {pr_title}
- URL: {pr_url}
- Base branch: {base_branch}
- Files changed: {changed_files}
- Lines added: {additions}, Lines removed: {deletions}

PR DESCRIPTION:
{pr_body[:2000] if pr_body else "(no description)"}
{diff_section}

OBJECTIVE:
Perform a security-focused code review to identify HIGH-CONFIDENCE security vulnerabilities
that could have real exploitation potential. This is NOT a general code review — focus ONLY
on security implications newly introduced by this PR. Do not comment on pre-existing issues.

CRITICAL INSTRUCTIONS:
1. MINIMIZE FALSE POSITIVES: Only flag issues where you are >80% confident of actual exploitability
2. AVOID NOISE: Skip theoretical issues, style concerns, or low-impact findings
3. FOCUS ON IMPACT: Prioritize vulnerabilities leading to unauthorized access, data breaches, or system compromise
4. DO NOT REPORT:
   - Denial of Service (DOS) vulnerabilities
   - Secrets or sensitive data stored on disk (handled by separate processes)
   - Rate limiting or resource exhaustion issues

SECURITY CATEGORIES TO EXAMINE:

**Input Validation Vulnerabilities:**
- SQL injection via unsanitized user input
- Command injection in system calls or subprocesses
- XXE injection in XML parsing
- Template injection in templating engines
- NoSQL injection in database queries
- Path traversal in file operations

**Authentication & Authorization Issues:**
- Authentication bypass logic
- Privilege escalation paths
- Session management flaws
- JWT token vulnerabilities
- Authorization logic bypasses (IDOR, missing checks)

**Crypto & Secrets Management:**
- Hardcoded API keys, passwords, or tokens
- Weak cryptographic algorithms or implementations
- Improper key storage or management
- Cryptographic randomness issues
- Certificate validation bypasses

**Injection & Code Execution:**
- Remote code execution via deserialization
- Pickle injection in Python
- YAML deserialization vulnerabilities
- Eval injection in dynamic code execution
- XSS vulnerabilities in web applications (reflected, stored, DOM-based)

**Data Exposure:**
- Sensitive data logging or storage
- PII handling violations
- API endpoint data leakage
- Debug information exposure
{custom_section}
ANALYSIS METHODOLOGY:

Phase 1 - Repository Context Research:
- Identify existing security frameworks and libraries in use
- Look for established secure coding patterns in the codebase
- Examine existing sanitization and validation patterns
- Understand the project's security model and threat model

Phase 2 - Comparative Analysis:
- Compare new code changes against existing security patterns
- Identify deviations from established secure practices
- Look for inconsistent security implementations
- Flag code that introduces new attack surfaces

Phase 3 - Vulnerability Assessment:
- Examine each modified file for security implications
- Trace data flow from user inputs to sensitive operations
- Look for privilege boundaries being crossed unsafely
- Identify injection points and unsafe deserialization

SEVERITY GUIDELINES:
- HIGH: Directly exploitable vulnerabilities leading to RCE, data breach, or authentication bypass
- MEDIUM: Vulnerabilities requiring specific conditions but with significant impact
- LOW: Defense-in-depth issues or lower-impact vulnerabilities

CONFIDENCE SCORING:
- 0.9-1.0: Certain exploit path identified
- 0.8-0.9: Clear vulnerability pattern with known exploitation methods
- 0.7-0.8: Suspicious pattern requiring specific conditions to exploit
- Below 0.7: Do NOT report (too speculative)

FALSE POSITIVE FILTERING — automatically exclude:
1. Denial of Service (DOS) or resource exhaustion
2. Secrets/credentials stored on disk if otherwise secured
3. Rate limiting concerns
4. Memory/CPU exhaustion issues
5. Lack of input validation without proven security impact
6. Input sanitization in GitHub Action workflows unless clearly triggerable
7. Lack of hardening (only flag concrete vulnerabilities)
8. Theoretical race conditions
9. Outdated third-party library vulnerabilities
10. Memory safety issues in memory-safe languages (Rust, Go, etc.)
11. Issues only in unit test files
12. Log spoofing (un-sanitized output to logs is not a vulnerability)
13. SSRF only controlling path (not host or protocol)
14. User-controlled content in AI prompts
15. Regex injection or Regex DOS
16. Issues in documentation or markdown files
17. Lack of audit logs is not a vulnerability

PRECEDENTS:
1. Logging high-value secrets (passwords, tokens) IS a vulnerability. Logging URLs is safe.
2. UUIDs are assumed unguessable.
3. Environment variables and CLI flags are trusted values.
4. React and Angular are generally XSS-safe unless using dangerouslySetInnerHTML or bypassSecurityTrustHtml.
5. Client-side JS/TS lack of auth checks is NOT a vulnerability.
6. GitHub Action workflow vulnerabilities must have a concrete, specific attack path.

REQUIRED OUTPUT FORMAT:
Return ONLY a JSON object with this exact structure. No markdown, no prose, no code blocks:

{{
  "findings": [
    {{
      "file": "path/to/file.py",
      "line": 42,
      "severity": "HIGH",
      "category": "sql_injection",
      "description": "...",
      "exploit_scenario": "...",
      "recommendation": "...",
      "confidence": 0.95
    }}
  ],
  "analysis_summary": {{
    "files_reviewed": 8,
    "high_severity": 1,
    "medium_severity": 0,
    "low_severity": 0,
    "review_completed": true
  }}
}}

If no vulnerabilities are found, return an empty findings array.

BEGIN SECURITY ANALYSIS NOW.
"""
