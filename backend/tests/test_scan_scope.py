from app.services.scan_scope import (
    authorized_scope_from_target_query,
    is_already_specific_subdomain,
    is_host_in_scope,
    registrable_domain,
)


def test_authorized_scope_parses_semicolon_multi_target_query() -> None:
    scope = authorized_scope_from_target_query(
        "www.cff.interprint.com.br;www.confea.interprint.com.br;adp.services-valid.com.br"
    )

    assert scope == [
        "adp.services-valid.com.br",
        "www.cff.interprint.com.br",
        "www.confea.interprint.com.br",
    ]
    assert is_host_in_scope("adp.services-valid.com.br", scope) is True
    assert is_host_in_scope("www.cff.interprint.com.br", scope) is True


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


def test_leaf_subdomain_under_two_label_suffix_is_already_specific() -> None:
    assert is_already_specific_subdomain("df.si.valid.com.br") is True
    assert is_already_specific_subdomain("si.valid.com.br") is True


def test_apex_domain_under_two_label_suffix_is_not_already_specific() -> None:
    assert is_already_specific_subdomain("valid.com.br") is False


def test_leaf_subdomain_under_one_label_suffix_is_already_specific() -> None:
    assert is_already_specific_subdomain("sub.valid.com") is True
    assert is_already_specific_subdomain("www.valid.com") is True


def test_apex_domain_under_one_label_suffix_is_not_already_specific() -> None:
    assert is_already_specific_subdomain("valid.com") is False


def test_bare_two_label_input_is_never_already_specific() -> None:
    assert is_already_specific_subdomain("valid.com") is False
    assert is_already_specific_subdomain("com.br") is False


def test_ip_target_is_not_already_specific_subdomain() -> None:
    assert is_already_specific_subdomain("192.168.1.10") is False


def test_url_input_is_normalized_before_checking() -> None:
    assert is_already_specific_subdomain("https://df.si.valid.com.br/path") is True
    assert is_already_specific_subdomain("https://valid.com.br/path") is False


# ── registrable_domain: shares the apex heuristic with is_already_specific_subdomain ──

def test_registrable_domain_of_a_hyphenated_sibling_domain() -> None:
    # "services-valid" is one hyphenated label, not "services" + "valid" --
    # its direct registrable parent is genuinely services-valid.com.br, a
    # different domain from valid.com.br. This is real DNS label math, not a
    # value copied from any specific report.
    assert registrable_domain("api-messaging.services-valid.com.br") == "services-valid.com.br"


def test_registrable_domain_of_a_deep_subdomain() -> None:
    assert registrable_domain("df.si.valid.com.br") == "valid.com.br"


def test_registrable_domain_of_an_apex_is_itself() -> None:
    assert registrable_domain("valid.com.br") == "valid.com.br"
    assert registrable_domain("valid.com") == "valid.com"


def test_registrable_domain_of_ip_returns_the_ip_unchanged() -> None:
    assert registrable_domain("192.168.1.10") == "192.168.1.10"


def test_registrable_domain_of_blank_input_is_empty() -> None:
    assert registrable_domain("") == ""
