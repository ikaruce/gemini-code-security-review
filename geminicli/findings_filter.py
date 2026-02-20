"""Findings filter to reduce false positives in security audit results."""

import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from geminicli.logger import get_logger

logger = get_logger(__name__)


@dataclass
class FilterStats:
    """Statistics about the filtering process."""

    total_findings: int = 0
    hard_excluded: int = 0
    kept_findings: int = 0
    exclusion_breakdown: Dict[str, int] = field(default_factory=dict)
    runtime_seconds: float = 0.0


class HardExclusionRules:
    """Regex-based hard exclusion rules for common false positives."""

    DOS_PATTERNS = re.compile(
        r"denial.of.service|dos.attack|resource.exhaust|cpu.exhaust|"
        r"memory.exhaust|bandwidth.exhaust|disk.exhaust",
        re.IGNORECASE,
    )

    RATE_LIMITING_PATTERNS = re.compile(
        r"rate.limit|throttl|brute.force.protection|request.flood",
        re.IGNORECASE,
    )

    RESOURCE_PATTERNS = re.compile(
        r"memory.leak|file.descriptor.leak|resource.leak|"
        r"unclosed.resource|connection.leak",
        re.IGNORECASE,
    )

    OPEN_REDIRECT_PATTERNS = re.compile(
        r"open.redirect|unvalidated.redirect",
        re.IGNORECASE,
    )

    MEMORY_SAFETY_PATTERNS = re.compile(
        r"buffer.overflow|use.after.free|out.of.bounds|"
        r"heap.overflow|stack.overflow|dangling.pointer",
        re.IGNORECASE,
    )

    REGEX_INJECTION_PATTERNS = re.compile(
        r"regex.injection|regexp.injection|redos|regex.dos",
        re.IGNORECASE,
    )

    LOG_SPOOFING_PATTERNS = re.compile(
        r"log.spoofing|log.injection|log.forging",
        re.IGNORECASE,
    )

    MISSING_AUDIT_LOG_PATTERNS = re.compile(
        r"audit.log|missing.log|insufficient.log",
        re.IGNORECASE,
    )

    HARDENING_PATTERNS = re.compile(
        r"lack.of.hardening|missing.hardening|should.implement|"
        r"recommended.to.add|best.practice",
        re.IGNORECASE,
    )

    MEMORY_SAFE_LANGS = re.compile(r"\.(rs|go)$", re.IGNORECASE)

    EXCLUDED_CATEGORIES = {
        "dos",
        "denial_of_service",
        "rate_limiting",
        "resource_exhaustion",
        "memory_leak",
        "regex_injection",
        "regex_dos",
        "log_spoofing",
        "open_redirect",
        "missing_audit_log",
    }

    @classmethod
    def get_exclusion_reason(cls, finding: Dict[str, Any]) -> Optional[str]:
        """Return the exclusion reason if the finding matches hard rules, else None."""
        category = finding.get("category", "").lower().replace("-", "_")
        description = finding.get("description", "")
        file_path = finding.get("file", "")

        if category in cls.EXCLUDED_CATEGORIES:
            return f"excluded_category:{category}"

        if cls.DOS_PATTERNS.search(description):
            return "dos_pattern"
        if cls.RATE_LIMITING_PATTERNS.search(description):
            return "rate_limiting_pattern"
        if cls.RESOURCE_PATTERNS.search(description):
            return "resource_leak_pattern"
        if cls.OPEN_REDIRECT_PATTERNS.search(description):
            return "open_redirect_pattern"
        if cls.REGEX_INJECTION_PATTERNS.search(description):
            return "regex_injection_pattern"
        if cls.LOG_SPOOFING_PATTERNS.search(description):
            return "log_spoofing_pattern"
        if cls.MISSING_AUDIT_LOG_PATTERNS.search(description):
            return "missing_audit_log_pattern"
        if cls.HARDENING_PATTERNS.search(description):
            return "hardening_best_practice"

        if cls.MEMORY_SAFETY_PATTERNS.search(description) and cls.MEMORY_SAFE_LANGS.search(
            file_path
        ):
            return "memory_safety_in_safe_language"

        if _is_test_file(file_path):
            return "test_file_only"

        if file_path.endswith((".md", ".rst", ".txt", ".adoc")):
            return "documentation_file"

        return None


def _is_test_file(file_path: str) -> bool:
    """Heuristically determine if a file is a test file."""
    lower = file_path.lower()
    test_patterns = [
        "/test/", "/tests/", "/spec/", "/specs/",
        "_test.", ".test.", ".spec.",
        "test_", "_spec.",
    ]
    return any(p in lower for p in test_patterns)


class FindingsFilter:
    """Hard-rule based findings filter (regex only, no external API calls)."""

    def __init__(self, use_hard_exclusions: bool = True, **_kwargs):
        """Initialize the findings filter.

        Args:
            use_hard_exclusions: Apply regex-based hard rules (default: True)
        """
        self.use_hard_exclusions = use_hard_exclusions
        self._hard_rules = HardExclusionRules()

    def filter_findings(
        self,
        findings: List[Dict[str, Any]],
        pr_context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, Dict[str, Any], FilterStats]:
        """Filter security findings using hard exclusion rules.

        Args:
            findings: List of security findings
            pr_context: Unused, kept for API compatibility

        Returns:
            Tuple of (success, filtered_results, stats)
        """
        stats = FilterStats(total_findings=len(findings))
        start_time = time.time()

        kept = []
        excluded = []

        for finding in findings:
            if self.use_hard_exclusions:
                reason = self._hard_rules.get_exclusion_reason(finding)
                if reason:
                    finding = dict(finding)
                    finding["exclusion_reason"] = reason
                    excluded.append(finding)
                    stats.hard_excluded += 1
                    stats.exclusion_breakdown[reason] = (
                        stats.exclusion_breakdown.get(reason, 0) + 1
                    )
                    continue
            kept.append(finding)

        stats.kept_findings = len(kept)
        stats.runtime_seconds = time.time() - start_time

        result = {
            "filtered_findings": kept,
            "excluded_findings": excluded,
            "analysis_summary": {
                "total_findings": stats.total_findings,
                "kept_findings": stats.kept_findings,
                "excluded_findings": len(excluded),
                "exclusion_breakdown": stats.exclusion_breakdown,
                "runtime_seconds": round(stats.runtime_seconds, 2),
            },
        }

        return True, result, stats
