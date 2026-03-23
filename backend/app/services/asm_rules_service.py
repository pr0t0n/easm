"""
ASM Rules Service - Integrates ASM vulnerability rules into worker assessment.

Rules are loaded from ~/.easm/rules and applied during scan analysis.
Each rule defines:
  - id: unique identifier
  - name: human-readable name
  - description: detailed description
  - severity: critical|high|medium|low|info
  - tags: list of tags for categorization
  - patterns: regex patterns to detect vulnerabilities
  - remediation: steps to fix
  - references: CVSS/NVD links
"""

import json
import os
import re
from pathlib import Path
from typing import Any


class ASMRulesService:
    """Manages ASM vulnerability rules for worker assessment."""

    def __init__(self):
        """Initialize rules service and load rules from disk."""
        self.rules: dict[str, Any] = {}
        self.severity_index: dict[str, list[str]] = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": [],
        }
        self.tag_index: dict[str, list[str]] = {}
        self._load_rules()

    def _load_rules(self) -> None:
        """Load all ASM rules from ~/.easm/rules directory."""
        home = Path.home()
        rules_dir = home / ".easm" / "rules"

        # Fallback to project bundled rules if available
        project_rules = Path(__file__).parent.parent.parent.parent / "asm-rules"
        if project_rules.exists():
            rules_dir = project_rules

        if not rules_dir.exists():
            print(f"[!] Rules directory not found at {rules_dir}")
            return

        rule_files = list(rules_dir.rglob("*.json"))
        print(f"[*] Loading {len(rule_files)} rule files from {rules_dir}")

        for rule_file in rule_files:
            try:
                with open(rule_file) as f:
                    data = json.load(f)

                    # Handle multiple schema formats:
                    # 1) [ {rule}, {rule} ]
                    # 2) { ...rule }
                    # 3) { "rules": [ {rule}, ... ] }
                    if isinstance(data, list):
                        rules_list = data
                    elif isinstance(data, dict) and isinstance(data.get("rules"), list):
                        rules_list = data.get("rules", [])
                    else:
                        rules_list = [data]

                    for rule in rules_list:
                        rule_id = rule.get("id")
                        if not rule_id:
                            print(f"[!] Rule missing id in {rule_file}")
                            continue

                        self.rules[rule_id] = rule

                        # Index by severity
                        severity = rule.get("severity", "info").lower()
                        if severity in self.severity_index:
                            self.severity_index[severity].append(rule_id)

                        # Index by tags
                        for tag in rule.get("tags", []):
                            if tag not in self.tag_index:
                                self.tag_index[tag] = []
                            self.tag_index[tag].append(rule_id)

            except json.JSONDecodeError as e:
                print(f"[!] Invalid JSON in {rule_file}: {e}")
            except Exception as e:
                print(f"[!] Error loading {rule_file}: {e}")

        print(f"[+] Loaded {len(self.rules)} rules")
        print(
            f"[+] Severity distribution: "
            f"critical={len(self.severity_index['critical'])}, "
            f"high={len(self.severity_index['high'])}, "
            f"medium={len(self.severity_index['medium'])}, "
            f"low={len(self.severity_index['low'])}, "
            f"info={len(self.severity_index['info'])}"
        )

    def get_rule(self, rule_id: str) -> dict[str, Any] | None:
        """Get a rule by its ID."""
        return self.rules.get(rule_id)

    def get_rules_by_severity(self, severity: str) -> list[dict[str, Any]]:
        """Get all rules for a given severity level."""
        rule_ids = self.severity_index.get(severity.lower(), [])
        return [self.rules[rid] for rid in rule_ids]

    def get_rules_by_tag(self, tag: str) -> list[dict[str, Any]]:
        """Get all rules with a given tag."""
        rule_ids = self.tag_index.get(tag.lower(), [])
        return [self.rules[rid] for rid in rule_ids]

    def evaluate(self, output: str, tool_name: str = "") -> list[dict[str, Any]]:
        """
        Evaluate tool output against all applicable rules.
        Returns list of matching findings with severity and details.
        """
        findings: list[dict[str, Any]] = []

        # Filter rules by tool if applicable
        applicable_rules = self.rules.values()
        if tool_name:
            applicable_rules = [
                r for r in applicable_rules
                if tool_name.lower() in [t.lower() for t in r.get("tools", [])] or not r.get("tools")
            ]

        for rule in applicable_rules:
            patterns = rule.get("patterns", [])
            # Compat: rules with patterns object, ex: {"vulnerable": [...], "safe": [...]}
            if isinstance(patterns, dict):
                patterns = patterns.get("vulnerable", [])
            if not patterns:
                continue

            for pattern_obj in patterns:
                if isinstance(pattern_obj, str):
                    pattern = pattern_obj
                    pattern_type = "regex"
                elif isinstance(pattern_obj, dict):
                    pattern = pattern_obj.get("value", "")
                    pattern_type = pattern_obj.get("type", "regex")
                else:
                    continue

                try:
                    if pattern_type == "regex":
                        regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                        matches = regex.findall(output)
                        if matches:
                            findings.append(
                                {
                                    "rule_id": rule.get("id"),
                                    "title": rule.get("name"),
                                    "severity": rule.get("severity", "info"),
                                    "description": rule.get("description"),
                                    "remediation": rule.get("remediation"),
                                    "references": rule.get("references", []),
                                    "tags": rule.get("tags", []),
                                    "matches": [str(m) for m in matches[:5]],  # First 5 matches
                                    "match_count": len(matches),
                                }
                            )
                    elif pattern_type == "contains":
                        if pattern in output:
                            findings.append(
                                {
                                    "rule_id": rule.get("id"),
                                    "title": rule.get("name"),
                                    "severity": rule.get("severity", "info"),
                                    "description": rule.get("description"),
                                    "remediation": rule.get("remediation"),
                                    "references": rule.get("references", []),
                                    "tags": rule.get("tags", []),
                                    "matches": [pattern],
                                    "match_count": 1,
                                }
                            )
                except re.error as e:
                    print(f"[!] Invalid regex in rule {rule.get('id')}: {e}")

        return findings

    def risk_score_for_severity(self, severity: str) -> int:
        """Map ASM severity to risk score (1-9)."""
        sev = str(severity or "low").strip().lower()
        return {
            "critical": 9,
            "high": 7,
            "medium": 5,
            "low": 3,
            "info": 1,
        }.get(sev, 2)


# Singleton instance
_asm_service: ASMRulesService | None = None


def get_asm_rules_service() -> ASMRulesService:
    """Get or initialize the ASM rules service singleton."""
    global _asm_service
    if _asm_service is None:
        _asm_service = ASMRulesService()
    return _asm_service
