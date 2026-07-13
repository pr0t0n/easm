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
