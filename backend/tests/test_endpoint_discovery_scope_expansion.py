from app.services.endpoint_discovery import discovered_in_scope_hosts_for_testing
from app.services.endpoint_discovery import _extract_endpoints_from_result
from app.services.cross_target_propagator import _extract_san_domains


def test_new_in_scope_endpoint_hosts_enter_test_target_list() -> None:
    hosts = discovered_in_scope_hosts_for_testing(
        [
            "https://valid.com/profile",
            "https://api.valid.com/orders/1",
            "https://admin.valid.com/login",
            "https://avidabank.dk/login",
        ],
        ["valid.com"],
        {"valid.com"},
    )

    assert hosts == ["admin.valid.com", "api.valid.com"]


def test_exact_host_authorization_does_not_promote_sibling_subdomain() -> None:
    hosts = discovered_in_scope_hosts_for_testing(
        [
            "https://api.www.valid.com/orders/1",
            "https://ri.valid.com/report",
        ],
        ["www.valid.com"],
        {"www.valid.com"},
    )

    assert hosts == ["api.www.valid.com"]


def test_endpoint_extraction_sort_has_stable_tiebreaker() -> None:
    urls = _extract_endpoints_from_result(
        "katana",
        {"stdout_full": "https://api.valid.com/bb\nhttps://api.valid.com/aa\n"},
        "api.valid.com",
    )

    ordered = sorted(urls, key=lambda u: (0 if "login" in u else 1, len(u), u))

    assert ordered == ["https://api.valid.com/aa", "https://api.valid.com/bb"]


def test_certificate_san_extraction_is_deterministic() -> None:
    result = {"stdout_full": "DNS:z.valid.com DNS:a.valid.com DNS:m.valid.com DNS:a.valid.com"}

    assert _extract_san_domains(result) == ["a.valid.com", "m.valid.com", "z.valid.com"]
