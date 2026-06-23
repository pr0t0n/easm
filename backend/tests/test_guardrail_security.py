"""P20 — Testes de segurança do guardrail (SSOT em guardrail_policy).

Trava de regressão para P2 (guardrail aplicado no caminho direto ao Kali) e
P8 (dedup futura). A plataforma é um pentest AUTOMATIZADO: flags de IMPACTO
real (dump de conteúdo, shell de SO, escrita/exfiltração de arquivo, DoS,
brute-force destrutivo) NUNCA podem ser despachadas — só mapeamos a estrutura.

Se algum desses asserts quebrar, alguém afrouxou a deny-list: trate como
regressão de segurança, não como teste chato.
"""
from __future__ import annotations

from app.services.guardrail_policy import sanitize_tool_args


def test_sqlmap_blocks_content_extraction_keeps_structure_mapping():
    clean, removed = sanitize_tool_args(
        "sqlmap",
        ["--batch", "--dbs", "--tables", "--columns", "--dump", "--os-shell", "-u", "http://x"],
    )
    # IMPACTO: extração de conteúdo e shell de SO → bloqueados
    assert "--dump" in removed
    assert "--os-shell" in removed
    # MAPEAMENTO de estrutura → permitido (é o que a plataforma faz)
    assert "--dbs" in clean
    assert "--tables" in clean
    assert "--columns" in clean
    assert "--batch" in clean


def test_global_forbidden_flags_stripped_for_any_tool():
    for flag in ("--exfil", "--os-shell", "--file-write"):
        clean, removed = sanitize_tool_args("curl", [flag, "-s", "http://x"])
        assert flag in removed, f"{flag} deveria ser bloqueado globalmente"
        assert "-s" in clean


def test_nuclei_dangerous_tags_removed():
    clean, removed = sanitize_tool_args("nuclei", ["-tags", "dos,cve", "-u", "http://x"])
    # tag contendo dos/fuzzing-dos/intrusive → arg de tags inteiro removido
    assert any("dos" in r for r in removed)
    assert "-u" in clean


def test_hydra_thread_count_capped():
    clean, _removed = sanitize_tool_args("hydra", ["-t", "64", "-L", "u", "-P", "p", "tgt", "ssh"])
    # brute-force destrutivo: threads capadas (anti-lockout / anti-DoS)
    assert "8" in clean
    assert "64" not in clean


def test_benign_args_pass_through_untouched():
    args = ["-silent", "-jsonl", "-u", "https://example.com"]
    clean, removed = sanitize_tool_args("nuclei", args)
    assert clean == args
    assert removed == []


def test_empty_and_none_args_are_safe():
    assert sanitize_tool_args("sqlmap", None)[0] == []
    assert sanitize_tool_args("sqlmap", [])[0] == []
