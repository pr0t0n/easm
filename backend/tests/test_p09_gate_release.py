def test_p09_negative_template_signal_does_not_narrow_deep_test_targets():
    from app.workers.tasks import _p09_gate_release_targets

    qualified_http_targets = ["a.example.com", "b.example.com"]

    assert _p09_gate_release_targets(qualified_http_targets) == qualified_http_targets

