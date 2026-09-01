"""Marco 5: the report's "Quality Gate do Pentest" section only ever showed
the generic top-6 `gaps` titles -- scan_quality.py already computes much more
specific, plain-language explanations (depth_requirements.blocking_requirement_ids,
preflight_summary.non_success_reason_counts, and the operator_message fields
on auth_precondition_summary/business_logic_precondition_summary), they just
never reached the HTML. These tests cover the extracted, pure
_render_quality_gate_html() helper.
"""
from __future__ import annotations

from app.services.report_generator import _render_quality_gate_html


def _base_quality(**overrides):
    quality = {
        "score": 62.0,
        "grade": "C",
        "label": "Parcial",
        "quality_gate": {"status": "remediation_scheduled", "rounds": 1},
        "gaps": [{"title": "Cobertura de XSS armazenado", "action": "Rodar validador de render."}],
        "components": {"test_depth": {"score": 40.0}, "surface_coverage": {"score": 82.0}},
    }
    quality.update(overrides)
    return quality


def test_omits_explain_block_when_nothing_blocking():
    html = _render_quality_gate_html(_base_quality())

    assert "Quality Gate do Pentest" in html
    assert "Requisitos bloqueando de fato" not in html
    assert "Alvos não totalmente escaneados" not in html


def test_includes_blocking_requirement_ids_when_present():
    html = _render_quality_gate_html(_base_quality(
        depth_requirements={"blocking_requirement_ids": ["p13_access_control_business_logic_matrix"]},
    ))

    assert "Requisitos bloqueando de fato" in html
    assert "p13_access_control_business_logic_matrix" in html


def test_includes_non_success_reason_counts_when_present():
    html = _render_quality_gate_html(_base_quality(
        preflight_summary={"non_success_reason_counts": [{"reason": "dns_inconclusive", "count": 4}]},
    ))

    assert "Alvos não totalmente escaneados" in html
    assert "dns_inconclusive" in html
    assert "4" in html


def test_separates_absent_preconditions_from_unscanned_targets():
    html = _render_quality_gate_html(_base_quality(
        preflight_summary={
            "non_success_reason_buckets": {
                "actionable_pending": [],
                "precondition_absent": [
                    {
                        "reason": "skipped:applicability:required_evidence_absent:known_parameters",
                        "count": 2,
                    }
                ],
                "tool_failures": [],
                "other": [],
            },
        },
    ))

    assert "Alvos não totalmente escaneados" not in html
    assert "Testes não aplicáveis por falta de superfície/precondição" in html
    assert "required_evidence_absent:known_parameters" in html


def test_includes_auth_operator_message_only_when_blocked():
    blocked_html = _render_quality_gate_html(_base_quality(
        auth_precondition_summary={"blocked": True, "operator_message": "Precisa de duas identidades reais."},
    ))
    not_blocked_html = _render_quality_gate_html(_base_quality(
        auth_precondition_summary={"blocked": False, "operator_message": "Precisa de duas identidades reais."},
    ))

    assert "Precisa de duas identidades reais." in blocked_html
    assert "Precisa de duas identidades reais." not in not_blocked_html


def test_includes_business_logic_operator_message_only_when_blockers_present():
    blocked_html = _render_quality_gate_html(_base_quality(
        business_logic_precondition_summary={"blockers": {"missing_session": 3}, "operator_message": "Bloqueado por sessão ausente."},
    ))
    not_blocked_html = _render_quality_gate_html(_base_quality(
        business_logic_precondition_summary={"blockers": {}, "operator_message": "Bloqueado por sessão ausente."},
    ))

    assert "Bloqueado por sessão ausente." in blocked_html
    assert "Bloqueado por sessão ausente." not in not_blocked_html


def test_html_escapes_operator_message_content():
    html = _render_quality_gate_html(_base_quality(
        auth_precondition_summary={"blocked": True, "operator_message": "<script>alert(1)</script>"},
    ))

    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
