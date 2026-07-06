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
