"""_verify_xss_execution_once closes a real gap: static tools (nuclei-xss,
dalfox) can only ever tell you a payload is reflected in a response body,
never whether it actually executes in a real DOM -- which is exactly what
Juice Shop's own challenge-detection hooks (and any real XSS bug bounty
report) require to count as confirmed. This runs the same real-browser
proof-of-concept technique a human tester uses (inject the canonical
`<iframe src=javascript:alert(...)>` payload, watch for a real alert() call)
against every already-discovered query-parameter endpoint, generalizing to
any target with a query parameter. These tests mock execute_via_kali and
persist_finding_dicts, matching this repo's fake-db unit-test convention.
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
    def __init__(self, endpoint_rows=None):
        self._endpoint_rows = endpoint_rows or []
        self.added = []
        self.commits = 0
        self.rollbacks = 0

    def query(self, model):
        return _FakeQuery(self._endpoint_rows)

    def add(self, row):
        self.added.append(row)

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1


def _job():
    return SimpleNamespace(id=21, state_data={})


def _endpoint(url):
    return SimpleNamespace(url=url, method="GET")


def test_skips_when_already_attempted():
    job = SimpleNamespace(id=21, state_data={"_xss_verification_attempted": True})

    result = runner._verify_xss_execution_once(_FakeDb(), job, "http://target.local")

    assert result == {"skipped": True, "reason": "already_attempted"}


def test_no_query_parameter_endpoints_is_a_clean_noop():
    db = _FakeDb(endpoint_rows=[_endpoint("http://target.local/api/Products")])

    result = runner._verify_xss_execution_once(db, _job(), "http://target.local")

    assert result == {"tested": 0}


def test_confirmed_trigger_persists_a_high_severity_finding(monkeypatch):
    import app.services.kali_executor as kali_executor_module
    import app.services.findings_extractor as findings_module

    payload = {
        "tested": 2,
        "triggered": [
            {"url": "http://target.local/rest/products/search?q=test", "param": "q",
             "test_url": "http://target.local/rest/products/search?q=%3Ciframe..."},
        ],
    }
    call_args = {}

    def _fake_execute(tool, target, **kwargs):
        call_args["tool"] = tool
        call_args["kwargs"] = kwargs
        return {"stdout": json.dumps(payload)}

    monkeypatch.setattr(kali_executor_module, "execute_via_kali", _fake_execute)

    persist_calls = []
    monkeypatch.setattr(
        findings_module, "persist_finding_dicts",
        lambda db, job, raw, **kw: persist_calls.append((raw, kw)),
    )

    db = _FakeDb(endpoint_rows=[_endpoint("http://target.local/rest/products/search?q=test")])
    job = _job()
    result = runner._verify_xss_execution_once(db, job, "http://target.local")

    assert result == {"tested": 2, "triggered": 1}
    assert call_args["tool"] == "xss-verification-probe"
    assert call_args["kwargs"]["extra_args"] == ["http://target.local/rest/products/search?q=test"]
    assert len(persist_calls) == 1
    raw, kwargs = persist_calls[0]
    assert len(raw) == 1
    assert raw[0]["severity"] == "high"
    assert raw[0]["details"]["verification_status"] == "confirmed"
    assert raw[0]["details"]["vuln_family"] == "xss"
    assert kwargs["default_tool"] == "xss_verification_probe"


def test_no_trigger_does_not_persist_anything(monkeypatch):
    import app.services.kali_executor as kali_executor_module
    import app.services.findings_extractor as findings_module

    monkeypatch.setattr(
        kali_executor_module, "execute_via_kali",
        lambda tool, target, **k: {"stdout": json.dumps({"tested": 3, "triggered": []})},
    )
    persist_calls = []
    monkeypatch.setattr(
        findings_module, "persist_finding_dicts",
        lambda db, job, raw, **kw: persist_calls.append(raw),
    )

    db = _FakeDb(endpoint_rows=[_endpoint("http://target.local/rest/products/search?q=test")])
    result = runner._verify_xss_execution_once(db, _job(), "http://target.local")

    assert result == {"tested": 3, "triggered": 0}
    assert persist_calls == []


def test_execute_via_kali_exception_is_caught_and_logged(monkeypatch):
    import app.services.kali_executor as kali_executor_module

    def _boom(*a, **k):
        raise RuntimeError("kali-runner unreachable")

    monkeypatch.setattr(kali_executor_module, "execute_via_kali", _boom)

    db = _FakeDb(endpoint_rows=[_endpoint("http://target.local/rest/products/search?q=test")])
    result = runner._verify_xss_execution_once(db, _job(), "http://target.local")

    assert "error" in result
    assert "kali-runner unreachable" in result["error"]
    assert db.rollbacks == 1
