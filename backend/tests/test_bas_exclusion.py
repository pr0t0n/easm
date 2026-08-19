"""bas_exclusion.exclude_simulated: the one-line filter every real
aggregation site (dashboard, cockpit, attack path, exploit chain, executive/
pentest reports) must apply so SIMULATED BAS Finding rows never contaminate
a real score or count -- but a REAL-agent BAS Finding must NOT be excluded,
since it's a genuine result."""
from __future__ import annotations

from types import SimpleNamespace

from app.services.bas_exclusion import BAS_FINDING_TOOL, exclude_simulated, is_bas_finding, is_simulated_bas_finding


class _FakeQuery:
    def __init__(self):
        self.filters = []

    def filter(self, *criteria):
        self.filters.extend(criteria)
        return self


def test_exclude_simulated_filters_on_both_tool_and_the_simulated_flag():
    query = exclude_simulated(_FakeQuery())
    assert len(query.filters) == 1
    compiled = str(query.filters[0].compile(compile_kwargs={"literal_binds": True}))
    assert "tool" in compiled
    assert "simulated" in compiled


def test_is_bas_finding_true_for_bas_tool():
    finding = SimpleNamespace(tool=BAS_FINDING_TOOL)
    assert is_bas_finding(finding) is True


def test_is_bas_finding_false_for_real_tool():
    finding = SimpleNamespace(tool="nuclei")
    assert is_bas_finding(finding) is False


def test_is_bas_finding_false_when_tool_missing():
    assert is_bas_finding(SimpleNamespace()) is False


def test_is_simulated_bas_finding_true_for_stub_dispatch():
    finding = SimpleNamespace(tool=BAS_FINDING_TOOL, details={"simulated": True})
    assert is_simulated_bas_finding(finding) is True


def test_is_simulated_bas_finding_false_for_real_agent_dispatch():
    finding = SimpleNamespace(tool=BAS_FINDING_TOOL, details={"simulated": False})
    assert is_simulated_bas_finding(finding) is False


def test_is_simulated_bas_finding_false_for_non_bas_finding():
    finding = SimpleNamespace(tool="nuclei", details={"simulated": True})
    assert is_simulated_bas_finding(finding) is False


def test_is_simulated_bas_finding_defaults_true_when_details_missing():
    """Missing details on a bas-agent Finding is treated as simulated --
    fail toward exclusion, never toward silently counting an ambiguous row."""
    finding = SimpleNamespace(tool=BAS_FINDING_TOOL, details=None)
    assert is_simulated_bas_finding(finding) is True
