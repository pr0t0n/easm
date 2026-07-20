from app.services.endpoint_discovery import discovered_in_scope_hosts_for_testing


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

