from app.services.scan_scope import is_host_in_scope


def test_exact_target_is_in_scope() -> None:
    assert is_host_in_scope("www.valid.com", ["www.valid.com"]) is True


def test_real_subdomain_of_target_is_in_scope() -> None:
    assert is_host_in_scope("api.www.valid.com", ["www.valid.com"]) is True


def test_sibling_subdomain_is_not_in_scope() -> None:
    # The incident this guards: a scan authorized for www.valid.com must
    # never treat ri.valid.com as in-scope just because they share a parent
    # domain — that is exactly what the old _root_domain/"mesmo domínio
    # registrável" check in endpoint_discovery.py got wrong.
    assert is_host_in_scope("ri.valid.com", ["www.valid.com"]) is False


def test_lookalike_suffix_is_not_in_scope() -> None:
    assert is_host_in_scope("www.valid.com.evil.com", ["www.valid.com"]) is False


def test_empty_scope_denies_by_default() -> None:
    # Unlike kali-runner's defense-in-depth check (which fails OPEN when no
    # scope is provided, for backward compat with pre-existing manual job
    # submissions), this call site is new and should fail CLOSED: if we
    # can't determine the authorized scope, don't reinject a target.
    assert is_host_in_scope("www.valid.com", []) is False


def test_empty_host_is_not_in_scope() -> None:
    assert is_host_in_scope("", ["www.valid.com"]) is False
