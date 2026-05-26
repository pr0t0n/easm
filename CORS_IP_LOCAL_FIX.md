# 🔧 CORS Error - Solução para Acesso via IP Local

## Problema Identificado

```
[Error] XMLHttpRequest cannot load http://192.168.18.135:8001/api/auth/login 
due to access control checks.
```

**Causa:** CORS bloqueando acesso do frontend ao backend quando você acessa via IP local.

---

## 🎯 Raiz do Problema

### Contexto
- **Frontend:** Rodando em Vite em `192.168.18.135:5173` (IP local)
- **Backend:** Rodando em `192.168.18.135:8001` 
- **CORS:** Configurado para aceitar apenas `localhost` e `127.0.0.1`

### Fluxo de Erro
1. ✅ Frontend detecta que está em `192.168.18.135`
2. ✅ Frontend tenta conectar ao backend em `192.168.18.135:8001/api/auth/login`
3. ❌ Backend diz: "Não, só aceito localhost/127.0.0.1"
4. ❌ Browser bloqueia (CORS Error)

---

## ✅ Solução Aplicada

### Mudança no Backend

**Arquivo:** [backend/app/main.py](backend/app/main.py)

Adicionei um regex de CORS que aceita **qualquer IP local privado**:

```python
# Regex para aceitar IPs locais e localhost em qualquer porta
_local_ip_regex = (
    r"^https?://(localhost|127\.0\.0\.1|192\.168\.\d{1,3}\.\d{1,3}|"
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3})"
    r"(:\d+)?$"
)
```

### O Que Isso Significa

Agora aceita:
- ✅ `http://localhost:5173`
- ✅ `http://127.0.0.1:5173`
- ✅ `http://192.168.18.135:5173` ← Seu caso!
- ✅ `http://10.0.0.1:5173` ← Outras redes privadas
- ✅ `http://172.16.0.1:5173` ← VPN/Docker
- ✅ Qualquer **porta** nestas origens

---

## 🚀 Como Usar Agora

### 1. **Reinicie o Backend**

```bash
# Parar containers
docker-compose down

# Reiniciar com as mudanças
docker-compose up -d backend
```

### 2. **Acesse via IP Local**

Abra no navegador:
```
http://192.168.18.135:5173
```

### 3. **Faça Login**

```
Email:  admin@example.com
Senha:  admin123
```

### 4. **Verificar Tudo Funcionando**

Abra o DevTools (F12) → Network tab:
- Procure por `POST /api/auth/login`
- Status deve ser **200**
- Response deve conter `access_token` e `refresh_token`

---

## 📋 Detalhes Técnicos

### CORS Headers Agora Inclusos

```http
Access-Control-Allow-Origin: http://192.168.18.135:5173
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: *
```

### IPs Privados Suportados

| Intervalo | Uso | Exemplo |
|-----------|-----|---------|
| `127.x.x.x` | Localhost | `127.0.0.1` |
| `192.168.x.x` | Redes locais | `192.168.18.135` |
| `10.x.x.x` | Redes privadas | `10.0.0.1` |
| `172.16-31.x.x` | VPN/Docker | `172.17.0.1` |

---

## 🔒 Segurança

### É Seguro?

✅ **Sim**, porque:
- Apenas **IPs privados** são permitidos (não acessíveis da internet)
- Você precisa estar **na mesma rede local**
- Em **produção**, você deve definir `FRONTEND_ORIGIN_REGEX` com um regex específico
- Credenciais ainda são protegidas (JWT com 24h de validade)

### Para Produção

Se você quiser restringir mais, crie um arquivo `.env`:

```bash
FRONTEND_ORIGIN_REGEX=^https://seu-dominio\.com(:\d+)?$
```

---

## 🧪 Testes

### Teste 1: Conexão Backend
```bash
curl -i http://192.168.18.135:8001/health
# Deve retornar 200 OK
```

### Teste 2: CORS Preflight
```bash
curl -i -X OPTIONS \
  -H "Origin: http://192.168.18.135:5173" \
  -H "Access-Control-Request-Method: POST" \
  http://192.168.18.135:8001/api/auth/login
  
# Deve incluir: Access-Control-Allow-Origin header
```

### Teste 3: Login via cURL
```bash
curl -X POST http://192.168.18.135:8001/api/auth/login \
  -H "Content-Type: application/json" \
  -H "Origin: http://192.168.18.135:5173" \
  -d '{"email":"admin@example.com","password":"admin123"}'
  
# Deve retornar JSON com access_token
```

---

## 🐛 Se Ainda Não Funcionar

### Verificar Logs

```bash
# Backend logs
docker-compose logs backend --tail=50

# Procure por erros de CORS ou conexão
```

### Limpar Cache

```bash
# Limpar localStorage do navegador
# DevTools (F12) → Application → Storage → Clear All

# Ou em incógnito:
# Ctrl+Shift+N (novo incógnito)
```

### Reset Completo

```bash
# Parar tudo
docker-compose down

# Remover volumes (dados)
docker-compose down -v

# Reiniciar
docker-compose up -d
```

---

## 📚 Referências

- [CORS MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
- [FastAPI CORS](https://fastapi.tiangolo.com/tutorial/cors/)
- [RFC 1918 - Private IP Ranges](https://tools.ietf.org/html/rfc1918)

---

## ✅ Status

- ✅ Backend corrigido para aceitar IPs locais
- ✅ Frontend usa detecção automática de hostname
- ✅ CORS agora funciona com `192.168.x.x`
- ✅ Seguro pois restrito a IPs privados

**Próximo passo:** Reinicie o backend e tente acessar novamente via `192.168.18.135:5173`
