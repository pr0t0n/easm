"""Safe benchmark registry for pentest automation validation.

The registry turns external platform analysis into a product contract: which
labs are safe to run, what they validate, and what evidence the platform must
produce before we claim the agent improved.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class BenchmarkTarget:
    id: str
    name: str
    category: str
    source_url: str
    priority: int
    maturity: str
    safe_execution: str
    coverage: tuple[str, ...]
    expected_evidence: tuple[str, ...]
    recommended_profiles: tuple[str, ...] = field(default_factory=tuple)
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "source_url": self.source_url,
            "priority": self.priority,
            "maturity": self.maturity,
            "safe_execution": self.safe_execution,
            "coverage": list(self.coverage),
            "expected_evidence": list(self.expected_evidence),
            "recommended_profiles": list(self.recommended_profiles),
            "notes": self.notes,
        }


BENCHMARK_TARGETS: tuple[BenchmarkTarget, ...] = (
    BenchmarkTarget(
        id="vuln-bank",
        name="vuln-bank",
        category="web_api_code_ai_lab",
        source_url="https://github.com/Commando-X/vuln-bank",
        priority=1,
        maturity="active_lab",
        safe_execution="local_container_only",
        coverage=(
            "web_application",
            "api_security",
            "auth_access_control",
            "business_logic",
            "ai_integrated_app",
            "secure_code_review",
        ),
        expected_evidence=(
            "authenticated_request_pair",
            "baseline_vs_exploit_response",
            "finding_proof_pack",
            "phase_ledger_coverage",
        ),
        recommended_profiles=("operational", "reconnaissance", "delivery_exploitation", "post_exploitation"),
        notes="Best first benchmark because it exercises web, API, auth, AI app, and code-review workflows.",
    ),
    BenchmarkTarget(
        id="aigoat",
        name="AIGoat",
        category="llm_security_lab",
        source_url="https://github.com/AISecurityConsortium/AIGoat",
        priority=2,
        maturity="active_lab",
        safe_execution="local_container_only",
        coverage=(
            "owasp_llm_top_10",
            "prompt_injection",
            "insecure_output_handling",
            "sensitive_information_disclosure",
            "progressive_defenses",
        ),
        expected_evidence=(
            "prompt_attack_case",
            "model_response_transcript",
            "guardrail_decision",
            "canary_leak_check",
        ),
        recommended_profiles=("operational",),
        notes="Use to validate the platform's untrusted-content envelope and future AI security scan module.",
    ),
    BenchmarkTarget(
        id="dvaia",
        name="DVAIA",
        category="llm_rag_agent_lab",
        source_url="https://github.com/airtasystems/DVAIA-Damn-Vulnerable-AI-Application",
        priority=3,
        maturity="active_lab",
        safe_execution="local_container_only",
        coverage=(
            "llm_testing",
            "rag_testing",
            "multimodal_testing",
            "agent_testing",
            "prompt_payload_generation",
        ),
        expected_evidence=(
            "rag_query_case",
            "retrieved_context_excerpt",
            "prompt_injection_detection",
            "data_boundary_assessment",
        ),
        recommended_profiles=("operational",),
        notes="Useful after AIGoat, once RAG-specific checks are exposed as first-class scan items.",
    ),
    BenchmarkTarget(
        id="dvmcp",
        name="DVMCP",
        category="mcp_security_lab",
        source_url="https://github.com/of3r/DVMCP",
        priority=4,
        maturity="early_lab",
        safe_execution="local_container_only",
        coverage=(
            "mcp_tool_abuse",
            "agent_tool_context",
            "ollama_integrated_lab",
            "tool_boundary_testing",
        ),
        expected_evidence=(
            "mcp_tool_call_trace",
            "blocked_or_allowed_decision",
            "tool_argument_sanitization",
            "agent_context_boundary_check",
        ),
        recommended_profiles=("operational",),
        notes="Small project, but directly maps to the platform's MCP/Kali bridge risk surface.",
    ),
    BenchmarkTarget(
        id="network-attack-simulator",
        name="NetworkAttackSimulator",
        category="network_agent_simulation",
        source_url="https://github.com/Jjschwartz/NetworkAttackSimulator",
        priority=5,
        maturity="conceptual_stable",
        safe_execution="simulated_network_only",
        coverage=(
            "agent_planning",
            "network_path_reasoning",
            "lateral_movement_simulation",
            "benchmark_without_real_targets",
        ),
        expected_evidence=(
            "planned_attack_path",
            "state_transition_trace",
            "success_metric",
            "failed_action_reason",
        ),
        recommended_profiles=("operational", "reconnaissance"),
        notes="Use as an offline scoring harness, not as a production scanner dependency.",
    ),
)


AI_SECURITY_SUITES: tuple[BenchmarkTarget, ...] = (
    BenchmarkTarget(
        id="promptfoo",
        name="promptfoo",
        category="ai_red_team_suite",
        source_url="https://github.com/promptfoo/promptfoo",
        priority=1,
        maturity="high_traction_active",
        safe_execution="test_harness_only",
        coverage=("prompt_tests", "agent_tests", "rag_tests", "red_team_ci"),
        expected_evidence=("test_case_yaml", "assertion_result", "risk_category", "regression_score"),
        notes="Best candidate for CI-style AI/RAG regression tests.",
    ),
    BenchmarkTarget(
        id="garak",
        name="garak",
        category="llm_vulnerability_suite",
        source_url="https://github.com/NVIDIA/garak",
        priority=2,
        maturity="high_traction_active",
        safe_execution="test_harness_only",
        coverage=("llm_vulnerability_scanning", "probe_detector_split", "jailbreak_assessment"),
        expected_evidence=("probe_name", "detector_result", "model_output", "risk_score"),
        notes="Good reference model for separating probes, detectors, and policy decisions.",
    ),
    BenchmarkTarget(
        id="pyrit",
        name="PyRIT",
        category="generative_ai_risk_suite",
        source_url="https://github.com/microsoft/PyRIT",
        priority=3,
        maturity="high_traction_active",
        safe_execution="test_harness_only",
        coverage=("genai_risk_identification", "orchestrated_attacks", "scoring"),
        expected_evidence=("objective", "conversation_trace", "score", "risk_label"),
        notes="Useful reference for a richer adversarial prompt orchestration layer.",
    ),
    BenchmarkTarget(
        id="ai-infra-guard",
        name="AI-Infra-Guard",
        category="ai_infrastructure_security_suite",
        source_url="https://github.com/Tencent/AI-Infra-Guard",
        priority=4,
        maturity="high_traction_active",
        safe_execution="test_harness_only",
        coverage=("agent_scan", "skills_scan", "mcp_scan", "ai_infra_scan", "jailbreak_evaluation"),
        expected_evidence=("scan_module", "finding_trace", "policy_mapping", "remediation_hint"),
        notes="Strong product-shape reference for treating AI systems as infrastructure.",
    ),
)


def list_benchmark_targets(*, category: str | None = None, include_ai_suites: bool = True) -> list[dict[str, Any]]:
    records = list(BENCHMARK_TARGETS)
    if include_ai_suites:
        records.extend(AI_SECURITY_SUITES)
    if category:
        category_l = category.strip().lower()
        records = [item for item in records if item.category.lower() == category_l]
    return [item.to_dict() for item in sorted(records, key=lambda item: (item.priority, item.name.lower()))]


def benchmark_readiness_summary() -> dict[str, Any]:
    records = list(BENCHMARK_TARGETS)
    suites = list(AI_SECURITY_SUITES)
    coverage = sorted({label for item in records + suites for label in item.coverage})
    local_labs = [item for item in records if item.safe_execution.endswith("_only")]
    return {
        "total_targets": len(records),
        "total_ai_suites": len(suites),
        "priority_order": [item.id for item in sorted(records, key=lambda item: item.priority)],
        "first_milestone": "wire vuln-bank as a local benchmark scan and assert proof-pack quality",
        "coverage_labels": coverage,
        "safe_execution_modes": sorted({item.safe_execution for item in records + suites}),
        "local_only_target_count": len(local_labs),
        "acceptance_gates": [
            "benchmark target must run only in local/simulated scope",
            "critical/high findings require proof_pack or stay capped",
            "scan must persist phase ledger and tool evidence",
            "AI/RAG/MCP tests must preserve target-controlled text boundaries",
            "benchmark score must track false positives, evidence quality, and phase coverage",
        ],
    }
