from __future__ import annotations

from app.services.scan_intelligence import expand_targets_after_p01, extract_discovered_subdomains, refine_target_set


DNSENUM_WITH_WILDCARD = """
dnsenum VERSION:1.3.1

-----   tarcisio.blog   -----

Host's addresses:
__________________

tarcisio.blog.                           377      IN    A        72.60.2.144

Wildcard detection using: zmdyniqrzyac
_______________________________________

zmdyniqrzyac.tarcisio.blog.              377      IN    A        72.60.2.144

!!!!!!!!!!!!!!!!!!!!!!!!!!!!

 Wildcards detected, all subdomains will point to the same IP address
 Omitting results containing 72.60.2.144.

!!!!!!!!!!!!!!!!!!!!!!!!!!!!

Name Servers:
______________

ns-cloud-a4.googledomains.com.           4502     IN    A        216.239.38.106
ns-cloud-a3.googledomains.com.           4502     IN    A        216.239.36.106

Brute forcing with /usr/share/dnsenum/dns.txt:
_______________________________________________

www.tarcisio.blog.                       377      IN    A        72.60.2.144
link.tarcisio.blog:185.3.93.228

tarcisio.blog class C netranges:
_________________________________

 72.60.2.0/24

tarcisio.blog ip blocks:
_________________________

 72.60.2.144/32

done.
"""


def test_extract_discovered_subdomains_ignores_dnsenum_noise() -> None:
    assert extract_discovered_subdomains([{"stdout": DNSENUM_WITH_WILDCARD}], "Tarcisio.blog") == [
        "link.tarcisio.blog",
        "tarcisio.blog",
        "www.tarcisio.blog",
    ]


def test_expand_targets_prefers_parser_aware_mcp_results_over_contaminated_lista() -> None:
    state = {
        "lista_ativos": [
            "link.tarcisio.blog:185.3.93.228",
            "www.tarcisio.blog",
            "zmdyniqrzyac.tarcisio.blog.",
            "ns-cloud-a4.googledomains.com.",
            "72.60.2.0/24",
            "72.60.2.144/32",
            "done.",
        ]
    }

    assert expand_targets_after_p01(state, "Tarcisio.blog", [{"stdout": DNSENUM_WITH_WILDCARD}]) == [
        "tarcisio.blog",
        "link.tarcisio.blog",
        "www.tarcisio.blog",
    ]


def test_extract_discovered_subdomains_ignores_candidate_only_alterx() -> None:
    mcp_results = [
        {
            "tool_name": "alterx",
            "profile": "alterx_permutations",
            "stdout": "admin.tarcisio.blog\napi.tarcisio.blog\nwww.tarcisio.blog\n",
        },
        {
            "tool_name": "subfinder",
            "profile": "subfinder_passive",
            "stdout": "link.tarcisio.blog\nwww.tarcisio.blog\n",
        },
    ]

    assert extract_discovered_subdomains(mcp_results, "Tarcisio.blog") == [
        "link.tarcisio.blog",
        "www.tarcisio.blog",
    ]


def test_extract_discovered_subdomains_reads_dnsrecon_hosts_from_stderr_path_content() -> None:
    # Regression from scan #31: the Kali/MCP adapter put dnsrecon's stderr
    # content in stderr_path, and dnsrecon prefixes the useful host with a
    # timestamp instead of making it the first token in the line.
    dnsrecon_stderr = """
    [*] std: Performing General Enumeration against: validcertificadora.com.br...
    [*] std: 2026-07-25 23:01:08,880 - validcertificadora.com.br A 23.227.38.65
    [*] std: 2026-07-25 23:01:13,224 - www.validcertificadora.com.br CNAME shops.myshopify.com
    [*] std: 2026-07-25 23:01:14,109 - blog.validcertificadora.com.br CNAME aap-ipv4-blog.validcertificadora.com.br
    [*] std: 2026-07-25 23:01:15,057 - pad.validcertificadora.com.br CNAME aap-ipv4-pad.validcertificadora.com.br
    """

    assert extract_discovered_subdomains(
        [{"tool_name": "dnsrecon", "stderr_path": dnsrecon_stderr}],
        "validcertificadora.com.br",
    ) == [
        "aap-ipv4-blog.validcertificadora.com.br",
        "aap-ipv4-pad.validcertificadora.com.br",
        "blog.validcertificadora.com.br",
        "pad.validcertificadora.com.br",
        "www.validcertificadora.com.br",
    ]


def test_extract_discovered_subdomains_discards_unannounced_wildcard_bruteforce_flood() -> None:
    # Reproduces the real scan #7 incident against tarcisio.blog: dnsenum's own
    # self-check ("Host's addresses" empty -> no "Wildcard detection using:"
    # banner) never fired, so it brute-forced blind and every guessed label
    # under the wildcarded zone "resolved" to the same catch-all IP.
    header = (
        "dnsenum VERSION:1.3.1\n\n-----   tarcisio.blog   -----\n\n"
        "Host's addresses:\n__________________\n\n\n"
        "Name Servers:\n______________\n\n\n"
        "Brute forcing with /usr/share/dnsenum/dns.txt:\n"
        "_______________________________________________\n\n"
    )
    flood = "\n".join(
        f"guess{i}.tarcisio.blog.                 377      IN    A        72.60.2.144"
        for i in range(200)
    )
    dnsenum_unannounced_wildcard = header + flood + "\ndone.\n"

    assert extract_discovered_subdomains(
        [{"stdout": dnsenum_unannounced_wildcard}], "Tarcisio.blog"
    ) == []

    # A genuine (small) brute-force hit list from a non-wildcarded zone must
    # still come through untouched.
    small_hit_list = header + "\n".join(
        f"real{i}.tarcisio.blog.                 377      IN    A        203.0.113.{i}"
        for i in range(5)
    ) + "\ndone.\n"

    assert extract_discovered_subdomains(
        [{"stdout": small_hit_list}], "Tarcisio.blog"
    ) == ["real0.tarcisio.blog", "real1.tarcisio.blog", "real2.tarcisio.blog", "real3.tarcisio.blog", "real4.tarcisio.blog"]


def test_refine_target_set_rejects_external_hosts_and_ips_before_dns() -> None:
    refined = refine_target_set(
        "Tarcisio.blog",
        [
            "link.tarcisio.blog",
            "ns-cloud-a4.googledomains.com.",
            "72.60.2.0/24",
            "72.60.2.144/32",
            "done.",
        ],
        cap=1,
    )

    assert refined["live_targets"] == ["tarcisio.blog"]


def test_refine_target_set_sends_root_scope_to_dnsx(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_dnsx(hosts, timeout=180, authorized_scope=None):
        captured["hosts"] = hosts
        captured["authorized_scope"] = authorized_scope
        return {
            "valid.com": "1.1.1.1",
            "api.valid.com": "1.1.1.2",
        }

    monkeypatch.setattr(
        "app.services.scan_intelligence._resolve_hosts_via_kali_dnsx",
        fake_dnsx,
    )
    refined = refine_target_set("valid.com", ["api.valid.com"])

    assert captured["authorized_scope"] == ["valid.com"]
    assert refined["live_targets"] == ["valid.com", "api.valid.com"]


def test_refine_target_set_rejects_external_hostname_resolving_to_loopback(monkeypatch) -> None:
    def fake_dnsx(hosts, timeout=180, authorized_scope=None):
        return {
            "valid.com": "1.1.1.1",
            "api.valid.com": "1.1.1.2",
            "localhost.valid.com": "127.0.0.1",
        }

    monkeypatch.setattr(
        "app.services.scan_intelligence._resolve_hosts_via_kali_dnsx",
        fake_dnsx,
    )

    refined = refine_target_set(
        "valid.com",
        ["api.valid.com", "localhost.valid.com"],
    )

    assert refined["live_targets"] == ["valid.com", "api.valid.com"]
    assert refined["non_public_targets"] == ["localhost.valid.com"]
    assert "localhost.valid.com" not in refined["host_ip"]
