# Burp Suite Advanced Testing - Configuração Completa

## 📋 Visão Geral

Esta configuração integra **Burp Suite Professional** com capabilities avançadas para:

### 1️⃣ **Repeater** - Testes Manuais
- **IDOR (Insecure Direct Object Reference)**
  - Teste de IDs sequenciais
  - Análise de padrões hash/UUID
  - Previsão baseada em timestamp
  
- **SQL Injection (SQLi)**
  - UNION-based SQLi
  - Boolean-based blind SQLi
  - Time-based blind SQLi
  - Error-based SQLi

### 2️⃣ **Intruder** - Testes Automatizados
- Fuzzing de diretórios e parâmetros
- Testes de injeção SQL automatizados
- Testes de XSS em massa
- Testes de Rate Limiting
- Testes de Local File Inclusion (LFI)

---

## 📦 Componentes Instalados

### Wordlists Baixadas
Automaticamente baixadas durante a construção do Docker:

```
/opt/burp-wordlists/
├── discovery/
│   ├── directory_list_2.3_medium.txt (85KB)
│   ├── fuzz_php_special.txt
│   ├── lfi_all.txt
│   ├── top_subdomains.txt
│   ├── common.txt
│   ├── common_sql_tables.txt
│   └── apache_user_enum_2.0.txt
│
├── vulnerabilities/
│   ├── sql_inj.txt
│   ├── sql.txt
│   ├── xss.txt
│   ├── ssti.txt
│   ├── directory_traversal.txt
│   ├── all_attacks.txt
│   ├── jboss.txt
│   ├── sap.txt
│   ├── sharepoint.txt
│   ├── weblogic.txt
│   ├── websphere.txt
│   └── xxe.txt
│
├── credentials/
│   ├── portuguese.txt
│   └── rockyou.txt
│
└── common/
    └── common.txt
```

### Configurações de Burp
```
/opt/burp-config/
├── intruder-attacks.yaml         # Configurações de Intruder
├── repeater-idor-sqli.yaml       # Guia de Repeater
├── burp_repeater_helper.py       # Utilitários Python
├── burp-intruder-config.json     # Config JSON
├── burp-env.sh                   # Variáveis de ambiente
└── BURP_ADVANCED_TESTING.md      # Documentação detalhada
```

### Módulo Python
```
backend/app/services/burp_advanced_testing.py
- IDORTester: Geração de payloads IDOR
- SQLiTester: Geração e detecção de payloads SQLi
- BurpIntruderConfig: Configuração de ataques Intruder
- BurpRepeaterHelper: Auxiliares para Repeater
```

---

## 🚀 Como Usar

### Opção 1: Repeater - Testes Manuais (Recomendado para Inicial)

#### IDOR Testing

```python
from app.services.tool_adapters import configure_burp_repeater_idor

# Configurar testes IDOR
config = configure_burp_repeater_idor(
    target_url="http://localhost:3001/api/users/123",
    parameter="id",
    original_value="123",
    test_type="sequential"  # ou: hash, uuid, timestamp
)

# Resultado: Lista de payloads para testar manualmente no Repeater
# Exemplo: /api/users/124, /api/users/125, /api/users/126, ...
```

**Workflow Manual:**
1. Capture a requisição original no Burp Proxy
2. Envie para **Repeater** (Ctrl+R)
3. Use as payloads sugeridas de `test_payloads`
4. Observe se dados não autorizados são retornados
5. Compare respostas para detectar IDOR

#### SQL Injection Testing

```python
from app.services.tool_adapters import configure_burp_repeater_sqli

# Configurar testes SQLi
config = configure_burp_repeater_sqli(
    target_url="http://localhost:3001/search?q=product",
    parameter="q",
    payload_type="union"  # ou: boolean, time, error, all
)

# Resultado: Payloads SQLi para testar manualmente
# Exemplo: q=' UNION SELECT version(),NULL,NULL --
```

**Workflow Manual:**
1. Capture a requisição original
2. Envie para **Repeater**
3. Substitua o parâmetro com valores de `test_payloads`
4. Procure por indicadores de SQLi:
   - UNION: Dados inesperados na resposta
   - Boolean: Respostas diferentes para true vs false
   - Time: Resposta demora ~5 segundos
   - Error: Mensagens de erro SQL na resposta

---

### Opção 2: Intruder - Testes Automatizados

#### Fuzzing de Diretórios

```python
from app.services.tool_adapters import configure_burp_intruder_attack

# Configurar ataque de fuzzing
config = configure_burp_intruder_attack(
    target_url="http://localhost:3001/",
    parameter="path",  # No URL: /FUZZ
    wordlist_type="discovery"
)

# Configuração:
# - Threads: 10
# - Wordlist: /opt/burp-wordlists/discovery/directory_list_2.3_medium.txt
# - Filter: Status != 404
```

**Workflow:**
1. Abra Burp Intruder
2. Conteúdo do `config["attack"]["wordlist"]` = caminho da wordlist
3. Posicione `§FUZZ§` no parâmetro em questão
4. Attack Type: **Sniper**
5. Payload: **Load from [wordlist_path]**
6. Options: Threads=10, Response Filter: `!404`

#### Testes de SQLi Automatizados

```python
config = configure_burp_intruder_attack(
    target_url="http://localhost:3001/search?q=",
    parameter="q",
    wordlist_type="vulnerabilities"
)

# Resultado:
# - Threads: 5 (mais lento para vulnerabilidades)
# - Wordlist: /opt/burp-wordlists/vulnerabilities/sql_inj.txt
# - Filter: Status 500 OR contains "error"
```

#### Testes de Rate Limiting

```python
# Usar Intruder com Battering Ram para teste de rate limit
config = configure_burp_intruder_attack(
    target_url="http://localhost:3001/api/data",
    parameter="request_body",
    wordlist_type="common"
)

# Modificar para testes rápidos:
# - Threads: 50 (alto para teste de rate limit)
# - Delay: 0ms
# - Monitor status 429 ou keywords: "rate", "throttle"
```

---

## 🔍 Detecção Automática de Timing-based SQLi

```python
from app.services.tool_adapters import detect_burp_sqli_timing

# Medir baseline de um parâmetro normal
# Depois testar com payload de delay

result = detect_burp_sqli_timing(
    baseline_time=0.5,      # Tempo normal: 500ms
    test_time=5.8,          # Tempo com SLEEP(5): 5800ms
    threshold=2.0
)

# Resultado: {
#   "is_vulnerable": True,
#   "confidence_score": 95.0,
#   "interpretation": "Time-based blind SQLi likely vulnerable"
# }
```

---

## 📊 Exemplos de Ataques

### Exemplo 1: IDOR Test Sequencial

**Request Original:**
```http
GET /api/users/100/profile HTTP/1.1
Host: localhost:3001
Authorization: Bearer token123
```

**Payloads Sugeridos:**
```
/api/users/101/profile  → Dados do usuário 101?
/api/users/102/profile  → Dados do usuário 102?
/api/users/1/profile    → Dados do admin?
/api/users/999/profile  → Out of range?
```

**Indicador de Vulnerabilidade:**
```json
{
  "status": "success",
  "user": {
    "id": 101,
    "email": "user101@example.com",  ← Acesso não autorizado!
    "role": "admin"
  }
}
```

---

### Exemplo 2: SQLi - UNION Based

**Request Original:**
```html
GET /search?q=laptop HTTP/1.1
```

**Payload:**
```
q=' UNION SELECT database(),user(),version() --
```

**Resposta Esperada:**
```
Results for: easm | root | MySQL 8.0.32
```

---

### Exemplo 3: SQLi - Time-Based Blind

**Request Original:**
```html
GET /filter?category=electronics HTTP/1.1
```

**Payload:**
```
category=electronics' AND SLEEP(5) --
```

**Indicador de Vulnerabilidade:**
- Resposta normal: ~500ms
- Resposta com SLEEP(5): ~5500ms
- **Diferença > 4s = SQL Injection detectada**

---

## ⚙️ Integração com Python

### Usando no seu Código

```python
from app.services.burp_advanced_testing import (
    IDORTester,
    SQLiTester,
    BurpIntruderConfig,
    BurpRepeaterHelper
)

# 1. IDOR Testing
idor_tester = IDORTester()
payloads = idor_tester.generate_sequential_payloads("user_id", "100", count=50)
for payload in payloads:
    print(f"Test: {payload.test_value} - {payload.description}")

# 2. SQLi Testing
sqli_tester = SQLiTester()
sqli_payloads = sqli_tester.generate_basic_payloads("search", "union")
for payload in sqli_payloads:
    print(f"Payload: {payload.payload}")

# 3. Intruder Configuration
intruder = BurpIntruderConfig()
attack_config = intruder.generate_intruder_attack(
    target_url="http://target.com/search?q=",
    parameter="q",
    wordlist_path="/opt/burp-wordlists/vulnerabilities/sql_inj.txt",
    threads=8
)

# 4. Request Analysis
helper = BurpRepeaterHelper()
analysis = helper.analyze_request("""
    GET /api/user/123/settings HTTP/1.1
    Host: localhost:3001
""")
print(f"Vulnerable params: {analysis['potential_idor_params']}")
```

---

## 📈 Workflow Recomendado

### Fase 1: Reconhecimento
```bash
1. Use Burp Proxy para capturar tráfego
2. Identifique endpoints com parâmetros ID
3. Procure por endpoints que retornam dados sensíveis
```

### Fase 2: IDOR Testing Manual (Repeater)
```bash
1. Selecione endpoint suspeito
2. Use configure_burp_repeater_idor()
3. Teste sequencialmente no Repeater
4. Monitore para acesso não autorizado
```

### Fase 3: SQLi Testing Manual (Repeater)
```bash
1. Identifique parâmetros de entrada
2. Use configure_burp_repeater_sqli()
3. Teste time-based blind SQLi
4. Valide timing analysis
```

### Fase 4: Automação (Intruder)
```bash
1. Após validar manualmente
2. Use configure_burp_intruder_attack()
3. Automatize com Intruder
4. Processe resultados em massa
```

---

## 🛠️ Troubleshooting

### Wordlists não encontradas
```bash
# Verificar se estão instaladas
ls -lah /opt/burp-wordlists/discovery/
ls -lah /opt/burp-wordlists/vulnerabilities/

# Se não encontradas, reconstruir container:
docker compose --profile dev up -d --build backend
```

### Burp API não respondendo
```bash
# Verificar if Burp REST está rodando
docker compose --profile dev ps burp_rest

# Verificar logs
docker compose --profile dev logs burp_rest
```

### Import Error: burp_advanced_testing
```python
# Adicionar ao sys.path
import sys
sys.path.insert(0, '/Users/.../backend')

from app.services.burp_advanced_testing import IDORTester
```

---

## 📚 Referências Rápidas

| Feature | Arquivo | Função |
|---------|---------|--------|
| IDOR Testing | `burp_advanced_testing.py` | `IDORTester` |
| SQLi Testing | `burp_advanced_testing.py` | `SQLiTester` |
| Intruder Config | `tool_adapters.py` | `configure_burp_intruder_attack()` |
| Repeater IDOR | `tool_adapters.py` | `configure_burp_repeater_idor()` |
| Repeater SQLi | `tool_adapters.py` | `configure_burp_repeater_sqli()` |
| Timing Analysis | `tool_adapters.py` | `detect_burp_sqli_timing()` |

---

## 📋 Próximas Passos

1. **Rebuild Container**
   ```bash
   docker compose --profile dev up -d --build backend worker_unit_vuln
   ```

2. **Verify Wordlists**
   ```bash
   docker compose --profile dev exec backend ls -la /opt/burp-wordlists/
   ```

3. **Test IDOR Configuration**
   ```bash
   docker compose --profile dev exec backend python3 -c "
   from app.services.tool_adapters import configure_burp_repeater_idor
   config = configure_burp_repeater_idor('http://localhost:3001/api/users/123', 'id', '123')
   print(config['test_payloads'][:3])
   "
   ```

4. **Run Full Scan with New Capabilities**
   ```bash
   # Execute via API
   POST /api/scans
   {
     "target": "http://localhost:3001",
     "tools": ["burp-cli"],
     "enable_advanced": true
   }
   ```

---

## ✅ Verificação Final

- [x] Wordlists baixadas em `/opt/burp-wordlists/`
- [x] Configurações em `/opt/burp-config/`
- [x] Módulo Python `burp_advanced_testing.py` instalado
- [x] Funções em `tool_adapters.py` atualizadas
- [x] Dockerfile com scripts de configuração
- [x] Documentação completa fornecida

---

**Última atualização:** 27 de março de 2026
**Status:** ✅ Completo
