"""_disclose_confirmed_findings_once mirrors how a real pentest report
reaches a target that runs its own "tell us about vulnerabilities" contact
form -- it never invents a finding, it only forwards text this scan's own
tools (e.g. retire.js's vulnerable-library detection) already confirmed and
persisted, through whatever public feedback/contact channel the target
exposes (finding_disclosure_probe.py's generic REST convention wordlist).
These tests mock execute_via_kali and a fake Finding queryset, matching this
repo's fake-db unit-test convention.
"""
import json
from types import SimpleNamespace

from app.services import offensive_operator_runner as runner


class _FakeQuery:
    def __init__(self, rows):
        self._rows = rows

    def filter(self, *args, **kwargs):
        return self

    def order_by(self, *args, **kwargs):
        return self

    def limit(self, *args, **kwargs):
        return self

    def all(self):
        return self._rows


class _FakeDb:
    def __init__(self, finding_rows=None):
        self._finding_rows = finding_rows or []
        self.added = []
        self.commits = 0
        self.rollbacks = 0

    def query(self, model):
        return _FakeQuery(self._finding_rows)

    def add(self, row):
        self.added.append(row)

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1


def _job():
    return SimpleNamespace(id=33, state_data={})


def _finding(id_, title):
    return SimpleNamespace(id=id_, title=title)


def test_skips_when_already_attempted():
    job = SimpleNamespace(id=33, state_data={"_finding_disclosure_attempted": True})

    result = runner._disclose_confirmed_findings_once(_FakeDb(), job, "http://target.local")

    assert result == {"skipped": True, "reason": "already_attempted"}


def test_no_disclosure_worthy_findings_is_a_clean_noop():
    db = _FakeDb(finding_rows=[_finding(1, "Missing Content-Security-Policy header")])

    result = runner._disclose_confirmed_findings_once(db, _job(), "http://target.local")

    assert result == {"submitted": 0}


def test_vulnerable_component_finding_gets_submitted(monkeypatch):
    import app.services.kali_executor as kali_executor_module

    call_args = []

    def _fake_execute(tool, target, **kwargs):
        call_args.append((tool, kwargs))
        return {"stdout": json.dumps({"submitted": True, "endpoint": "http://target.local/api/Feedbacks"})}

    monkeypatch.setattr(kali_executor_module, "execute_via_kali", _fake_execute)

    db = _FakeDb(finding_rows=[
        _finding(1, "Vulnerable and outdated component: jquery 1.11.3 (CVE-2020-11022)"),
        _finding(2, "Missing X-Frame-Options header"),
    ])
    job = _job()
    result = runner._disclose_confirmed_findings_once(db, job, "http://target.local")

    assert result == {"submitted": 1, "attempted": 1}
    assert len(call_args) == 1
    tool, kwargs = call_args[0]
    assert tool == "finding-disclosure-probe"
    assert "jquery" in kwargs["extra_args"][0]
    assert job.state_data["_finding_disclosure_attempted"] is True


def test_caps_at_three_disclosure_candidates(monkeypatch):
    import app.services.kali_executor as kali_executor_module

    call_args = []
    monkeypatch.setattr(
        kali_executor_module, "execute_via_kali",
        lambda tool, target, **k: call_args.append(k) or {"stdout": json.dumps({"submitted": True})},
    )

    db = _FakeDb(finding_rows=[
        _finding(i, f"Vulnerable component #{i}") for i in range(1, 6)
    ])
    result = runner._disclose_confirmed_findings_once(db, _job(), "http://target.local")

    assert result == {"submitted": 3, "attempted": 3}
    assert len(call_args) == 3


def test_execute_via_kali_exception_is_caught_and_logged(monkeypatch):
    import app.services.kali_executor as kali_executor_module

    def _boom(*a, **k):
        raise RuntimeError("kali-runner unreachable")

    monkeypatch.setattr(kali_executor_module, "execute_via_kali", _boom)

    db = _FakeDb(finding_rows=[_finding(1, "Vulnerable component detected")])
    result = runner._disclose_confirmed_findings_once(db, _job(), "http://target.local")

    assert "error" in result
    assert "kali-runner unreachable" in result["error"]
    assert db.rollbacks == 1
