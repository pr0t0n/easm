from scripts import phase_tool_smoke_test


def test_phase_smoke_defaults_to_no_job_tabletop(monkeypatch, capsys) -> None:
    monkeypatch.setattr("sys.argv", ["phase_tool_smoke_test.py", "valid.com"])
    monkeypatch.setattr(
        phase_tool_smoke_test,
        "_post_job",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must not dispatch")),
    )

    assert phase_tool_smoke_test.main() == 0
    assert '"target_network_requests": 0' in capsys.readouterr().out


def test_phase_smoke_blocks_active_mode_without_attestation(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "sys.argv",
        ["phase_tool_smoke_test.py", "valid.com", "--execute"],
    )
    monkeypatch.setattr(
        phase_tool_smoke_test,
        "_post_job",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must not dispatch")),
    )

    assert phase_tool_smoke_test.main() == 2
    assert "No Kali jobs were started" in capsys.readouterr().err
