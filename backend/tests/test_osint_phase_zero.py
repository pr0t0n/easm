def test_github_dork_skips_without_token_by_default(monkeypatch):
    from app.services import osint_phase_zero

    monkeypatch.setattr(osint_phase_zero, "GITHUB_UNAUTH_ENABLED", False)

    result = osint_phase_zero.run_github_dork("validcertificadora.com.br", token=None)

    assert result["skipped"] == "no_github_token"
    assert result["queries_run"] == 0
    assert result["results_count"] == 0
    assert result["blocking"] is False


def test_github_dork_uses_bounded_timeout_when_enabled(monkeypatch):
    from app.services import osint_phase_zero

    calls = []

    class Response:
        status_code = 403

    def fake_get(url, *, headers, params, timeout):
        calls.append({"url": url, "timeout": timeout, "params": params})
        return Response()

    monkeypatch.setattr(osint_phase_zero, "GITHUB_UNAUTH_ENABLED", True)
    monkeypatch.setattr(osint_phase_zero, "GITHUB_DORK_TOTAL_BUDGET_SECONDS", 2.0)
    monkeypatch.setattr(osint_phase_zero.requests, "get", fake_get)

    result = osint_phase_zero.run_github_dork("validcertificadora.com.br", token=None)

    assert result["blocking"] is False
    assert result["errors"] == ["rate_limited"]
    assert calls
    assert isinstance(calls[0]["timeout"], tuple)
    assert calls[0]["timeout"][0] <= 2.0
    assert calls[0]["timeout"][1] <= 2.0
