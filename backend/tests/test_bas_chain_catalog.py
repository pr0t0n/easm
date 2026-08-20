"""bas_chain_catalog.py: named, ordered attack-chain sequences. Every
technique_key referenced by a chain must actually exist in the real
technique catalog -- a chain step referencing a typo'd/removed key would
silently no-op at dispatch time instead of failing loudly here."""
from __future__ import annotations

from app.services.bas_chain_catalog import get_chain, list_chains
from app.services.bas_technique_catalog import get_technique


def test_every_chain_step_references_a_real_technique():
    for chain in list_chains():
        for technique_key in chain["technique_keys"]:
            assert get_technique(technique_key) is not None, f"{chain['chain_key']} -> {technique_key}"


def test_every_chain_has_at_least_two_steps():
    """A one-step 'chain' isn't a sequence -- it's just a technique."""
    for chain in list_chains():
        assert len(chain["technique_keys"]) >= 2, chain["chain_key"]


def test_get_chain_returns_none_for_unknown_key():
    assert get_chain("does-not-exist") is None


def test_get_chain_returns_the_right_sequence():
    chain = get_chain("ad_enumeration_chain")
    assert chain is not None
    assert chain["technique_keys"] == [
        "network_share_discovery", "ad_scouting_ldap", "ad_bloodhound_collect", "ad_kerberoast",
    ]
