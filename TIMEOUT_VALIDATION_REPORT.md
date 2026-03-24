# Relatório de Validação de Timeouts - EASM

**Data:** 24 de março de 2026  
**Estado:** ⚠️ PARCIALMENTE CONFIGURADO

## Resumo Executivo

- ✅ **11 ferramentas** com timeout específico configurado
- ⚠️ **16 ferramentas** usando timeout padrão de 90s (potencialmente insuficiente)
- 🔴 **1 ferramenta** com timeout hardcoded (curl-headers = 25s)
- ⚠️ **Inconsistência**: sslscan e shcheck adicionadas recentemente, mas sem timeout específico

---

## Configuração Atual

### Timeout Padrão
```
TOOL_TIMEOUT_SECONDS = 90 segundos
```
**Onde está:** `backend/app/services/tool_adapters.py` (linha 24)

### Timeouts Específicos (11 ferramentas)

| Ferramenta | Timeout | Tempo esperado | Status |
|---|---|---|---|
| **nuclei** | 600s | 5-10 min por alvo | ✅ Bem configurado |
| **nmap** | 600s | 5-10 min em varredura completa | ✅ Bem configurado |
| **nmap-vulscan** | 600s | 5-10 min em varredura completa | ✅ Bem configurado |
| **vulscan** | 600s | Alias para nmap | ✅ Bem configurado |
| **sqlmap** | 300s | 3-5 min | ✅ Bem configurado |
| **nikto** | 240s | 2-4 min | ✅ Bem configurado |
| **wapiti** | 240s | 2-4 min | ✅ Bem configurado |
| **katana** | 180s | 2-3 min | ✅ Bem configurado |
| **ffuf** | 120s | 1-2 min | ✅ Bem configurado |
| **subfinder** | 120s | 1-2 min | ✅ Bem configurado |
| **amass** | 120s | 1-2 min | ✅ Bem configurado |

### Timeouts Padrão (90s) - POTENCIAL PROBLEMA
```
sslscan, shcheck, wafw00f, dalfox, commix, wpscan, 
zap, semgrep, tplmap, gowitness, uro, httpx, dirb, 
gobuster, wfuzz, certfinder
```

### Timeout Especial
- **curl-headers**: 25s (hardcoded em `_run_curl_headers_tool()`)
  - Linha 532 e 571 de tool_adapters.py
  - Usa `--max-time 20` internamente + 5s de margem

---

## 🔴 Problemas Identificados

### 1. **sslscan e shcheck - Sem timeout específico**
**Problema:** 
- Ferramentas adicionadas recentemente (commit: "Dockerfile: add perl+sslscan")
- Não têm timeout específico configurado
- Usam timeout padrão de 90s
- **SSL certificate scanning pode exceder 90s em servidores lentos**

**Impacto:** 
- Risco de timeout prematuro
- Resultados incompletos em varreduras mais longas

**Recomendação:**
```python
TOOL_SPECIFIC_TIMEOUTS = {
    ...
    "sslscan": 180,   # SSL scanning pode ser lento
    "shcheck": 120,   # Security headers check ~ 1-2 min
    ...
}
```

### 2. **curl-headers com timeout hardcoded (25s)**
**Problema:**
- Timeout não está em `TOOL_SPECIFIC_TIMEOUTS`
- Está hardcoded em 2 lugares na função `_run_curl_headers_tool()`
- Difícil de manter/atualizar centralmente

**Impacto:** 
- Não pode ser configurado dinamicamente
- Código duplicado (múltiplos hardcodes)

**Recomendação:**
```python
# Adicionar a TOOL_SPECIFIC_TIMEOUTS
TOOL_SPECIFIC_TIMEOUTS = {
    ...
    "curl-headers": 25,
}

# E referenciar em _run_curl_headers_tool()
timeout_seconds = TOOL_SPECIFIC_TIMEOUTS.get("curl-headers", 25)
```

### 3. **wafw00f sem timeout específico**
**Problema:**
- WAF detection pode levar tempo (múltiplas requisições)
- Usando timeout padrão de 90s
- Pode ser insuficiente em redes lentas

**Recomendação:**
```python
"wafw00f": 120,  # WAF detection ~ 1-2 min
```

### 4. **Ferramentas ZAP, Dalfox, Commix - Timeout padrão**
Essas ferramentas de fuzzing/automation precisam de mais tempo:
```python
"dalfox": 180,   # Fuzzing XSS 
"commix": 180,   # Fuzzing command injection
"zap": 300,      # Full security scanning
```

---

## ✅ Teste de Validação - Resultado

### Verificação de Implementação
```
✓ TOOL_TIMEOUT_SECONDS está definido
✓ TOOL_SPECIFIC_TIMEOUTS funciona via .get() com fallback
✓ subprocess.run() usa timeout_seconds corretamente
✓ TimeoutExpired é capturado e retorna mensagem clara
✓ curl-headers tem lógica separada mas funcional
```

### Arquivo de Configuração
- **Localização:** [backend/app/services/tool_adapters.py](backend/app/services/tool_adapters.py)
- **Linhas críticas:**
  - 24: `TOOL_TIMEOUT_SECONDS = 90`
  - 27-37: `TOOL_SPECIFIC_TIMEOUTS = {...}`
  - 422: `timeout_seconds = TOOL_SPECIFIC_TIMEOUTS.get(normalized_tool, TOOL_TIMEOUT_SECONDS)`
  - 429: `timeout=timeout_seconds`

---

## 📋 Recomendações Prioritárias

### 🔴 CRÍTICO (Implementar Imediatamente)
1. **Adicionar sslscan e shcheck a TOOL_SPECIFIC_TIMEOUTS**
   - sslscan: 180s
   - shcheck: 120s

### 🟡 IMPORTANTE (Próxima Sprint)
2. **Refatorar curl-headers**
   - Move timeout para TOOL_SPECIFIC_TIMEOUTS
   - Remove hardcodes duplicados
   
3. **Adicionar timeouts para ferramentas de fuzzing**
   - dalfox: 180s
   - commix: 180s
   - zap: 300s
   - wafw00f: 120s

### 🟢 OPCIONAL (Manutenção Contínua)
4. **Monitorar logs de timeout**
   - Adicionar metrics para TimeoutExpired
   - Alertar se muitos timeouts do mesmo tool
   - Considerar ajustar timeouts baseado em dados reais

---

## Plano de Implementação

### Fase 1: Critical Fix (5 minutos)
Adicionar sslscan e shcheck ao dicionário.

### Fase 2: Refactoring (10 minutos)
Refatorar curl-headers para usar dicionário centralizado.

### Fase 3: Growth (15 minutos)
Adicionar timeouts para dalfox, commix, zap, wafw00f.

---

## Referências de Tempo Esperado por Ferramenta

| Ferramenta | Tempo Típico | Tempo Máximo | Timeout Recomendado |
|---|---|---|---|
| curl-headers | 5-10s | 20s | 25s ✅ |
| httpx | 30-60s | 120s | 150s (↑ de 90s) |
| nuclei | 300-600s | 900s | 600s ✅ |
| nikto | 120-240s | 360s | 240s ✅ |
| nmap | 300-600s | 900s | 600s ✅ |
| wapiti | 120-240s | 360s | 240s ✅ |
| sslscan | 60-180s | 240s | 180s (↑ de 90s) |
| shcheck | 60-120s | 180s | 120s (↑ de 90s) |
| wafw00f | 60-120s | 180s | 120s (↑ de 90s) |
| dalfox | 120-180s | 300s | 180s (↑ de 90s) |
| commix | 120-180s | 300s | 180s (↑ de 90s) |
| sqlmap | 180-300s | 500s | 300s ✅ |
| zap | 300-600s | 900s | 300s-600s (↑ de 90s) |

---

## Checklist de Validação

- [x] Configuração de timeout default presente
- [x] TOOL_SPECIFIC_TIMEOUTS implementado
- [x] Mecanismo de fallback funcionando (.get com default)
- [x] TimeoutExpired é capturado e tratado
- [x] Mensagem de erro clara é retornada
- [ ] sslscan com timeout específico
- [ ] shcheck com timeout específico
- [ ] curl-headers refatorado para usar dicionário
- [ ] Teste end-to-end com ferramenta que exceda timeout
- [ ] Logs de timeout sendo monitorados

---

## Próximos Passos

1. **Implementar Phase 1 (Critical)** - adicionar sslscan/shcheck
2. **Executar teste** - validar que os novos timeouts funcionam
3. **Monitorar produção** - verificar se há mais ajustes necessários
4. **Documentar** - atualizar runbook com timeouts esperados
