#!/usr/bin/env python3
"""
Script de validação de timeouts de ferramentas
Verifica se os timeouts estão corretamente configurados no tool_adapters.py
"""

import sys
import re
from pathlib import Path


def validate_timeouts():
    """Validar configuração de timeouts"""
    
    tool_adapters = Path("backend/app/services/tool_adapters.py")
    
    if not tool_adapters.exists():
        print("❌ Arquivo tool_adapters.py não encontrado")
        return False
    
    with open(tool_adapters) as f:
        content = f.read()
    
    # Extrair TOOL_TIMEOUT_SECONDS
    match = re.search(r'TOOL_TIMEOUT_SECONDS\s*=\s*(\d+)', content)
    if not match:
        print("❌ TOOL_TIMEOUT_SECONDS não encontrado")
        return False
    
    default_timeout = int(match.group(1))
    print(f"✅ TOOL_TIMEOUT_SECONDS = {default_timeout}s")
    
    # Extrair TOOL_SPECIFIC_TIMEOUTS
    match = re.search(r'TOOL_SPECIFIC_TIMEOUTS\s*=\s*\{([^}]+)\}', content, re.DOTALL)
    if not match:
        print("❌ TOOL_SPECIFIC_TIMEOUTS não encontrado")
        return False
    
    timeouts_str = match.group(1)
    specific_timeouts = {}
    
    for line in timeouts_str.strip().split('\n'):
        if ':' in line and '"' in line:
            parts = line.split(':')
            if len(parts) == 2:
                key = parts[0].split('"')[1] if '"' in parts[0] else parts[0].strip()
                try:
                    val = int(parts[1].strip().rstrip(','))
                    specific_timeouts[key] = val
                except (ValueError, IndexError):
                    pass
    
    print(f"✅ TOOL_SPECIFIC_TIMEOUTS com {len(specific_timeouts)} ferramentas")
    
    # Validações críticas (Phase 1)
    critical_tools = {
        "sslscan": 180,
        "shcheck": 120,
        "wapiti": 240,
        "nikto": 240,
        "nuclei": 600,
        "nmap": 600,
        "curl-headers": 25,
    }
    
    print("\n" + "=" * 70)
    print("VALIDAÇÃO DE FERRAMENTAS CRÍTICAS")
    print("=" * 70)
    
    all_ok = True
    for tool, expected_timeout in critical_tools.items():
        actual_timeout = specific_timeouts.get(tool, default_timeout)
        if tool == "curl-headers":
            # curl-headers é especial - hardcoded em _run_curl_headers_tool
            if actual_timeout == expected_timeout:
                print(f"✅ {tool:20} → {actual_timeout}s (OK)")
            else:
                print(f"⚠️  {tool:20} → {actual_timeout}s (esperado {expected_timeout}s)")
        else:
            if actual_timeout == expected_timeout:
                print(f"✅ {tool:20} → {actual_timeout}s")
            else:
                print(f"❌ {tool:20} → {actual_timeout}s (esperado {expected_timeout}s)")
                all_ok = False
    
    # Verificar implementação
    print("\n" + "=" * 70)
    print("VERIFICAÇÃO DE IMPLEMENTAÇÃO")
    print("=" * 70)
    
    checks = {
        "TOOL_TIMEOUT_SECONDS definido": "TOOL_TIMEOUT_SECONDS = 90" in content,
        "TOOL_SPECIFIC_TIMEOUTS implementado": "TOOL_SPECIFIC_TIMEOUTS = {" in content,
        "timeout_seconds = TOOL_SPECIFIC_TIMEOUTS.get()": "timeout_seconds = TOOL_SPECIFIC_TIMEOUTS.get(normalized_tool, TOOL_TIMEOUT_SECONDS)" in content,
        "subprocess.run usa timeout": "timeout=timeout_seconds" in content,
        "TimeoutExpired é tratado": "except subprocess.TimeoutExpired:" in content,
        "_run_curl_headers_tool usa timeout": "timeout_seconds = TOOL_SPECIFIC_TIMEOUTS.get(\"curl-headers\"" in content,
    }
    
    for check_name, check_result in checks.items():
        status = "✅" if check_result else "❌"
        print(f"{status} {check_name}")
        if not check_result:
            all_ok = False
    
    # Verificar se há ferramentas sem timeout específico que deveriam ter
    print("\n" + "=" * 70)
    print("FERRAMENTAS COM TIMEOUT PADRÃO (90s)")
    print("=" * 70)
    
    tools_using_default = [
        "httpx", "dalfox", "commix", "zap", "wafw00f",
        "dirb", "gobuster", "wfuzz", "tplmap", "semgrep",
        "wpscan", "certfinder", "gowitness", "uro"
    ]
    
    has_missing = False
    for tool in tools_using_default:
        if tool not in specific_timeouts:
            print(f"⚠️  {tool:20} usando padrão 90s (possível timeout prematuro)")
            has_missing = True
    
    if not has_missing:
        print("✅ Nenhuma ferramenta crítica com timeout padrão insuficiente")
    
    # Resumo
    print("\n" + "=" * 70)
    print("RESUMO DA VALIDAÇÃO")
    print("=" * 70)
    
    if all_ok:
        print("✅ TODAS AS VALIDAÇÕES PASSARAM")
        print("\nTimeouts configurados corretamente:")
        print(f"  • Default: {default_timeout}s")
        print(f"  • Específicos: {len(specific_timeouts)} ferramentas")
        print("  • Implementação: OK")
        return True
    else:
        print("❌ ALGUMAS VALIDAÇÕES FALHARAM")
        return False


if __name__ == "__main__":
    ok = validate_timeouts()
    sys.exit(0 if ok else 1)
