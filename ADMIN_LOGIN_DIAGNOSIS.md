# 🔍 Diagnóstico: Acesso com admin@example.com

## Status: ✅ TUDO FUNCIONANDO

O problema **NÃO existe no backend**. O sistema de autenticação está funcionando normalmente.

---

## Validações Realizadas

### 1. ✅ Usuário Existe no Banco de Dados
- **Email**: admin@example.com
- **ID**: 1
- **Status**: Ativo (is_active = True)
- **Privilégio**: Admin (is_admin = True)
- **Senha**: ✅ Correta (admin123)

### 2. ✅ Banco de Dados Conecta com Sucesso
- **Database**: PostgreSQL (easm@postgres:5432/easm)
- **Status**: Conectando com sucesso

### 3. ✅ Login API Funciona
- **Endpoint**: POST /api/auth/login
- **Request**:
  ```json
  {
    "email": "admin@example.com",
    "password": "admin123"
  }
  ```
- **Response** (Status 200):
  ```json
  {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "bearer",
    "expires_in": 86400
  }
  ```

---

## 🎯 Conclusões

### Credenciais Corretas
```
Email:  admin@example.com
Senha:  admin123
```

### Possíveis Causas do Seu Problema

Se você está recebendo erro de acesso, pode ser:

1. **Frontend não está enviando a requisição corretamente**
   - Verifique o console do navegador (DevTools) → Network → POST /api/auth/login
   - Verifique se o JWT está sendo enviado em requisições subsequentes

2. **Senha incorreta no frontend**
   - Confirme que está digitando `admin123` (sem espaços)

3. **CORS ou problema de conexão**
   - Verifique se o frontend consegue se conectar ao http://localhost:8001

4. **Token expirado**
   - Tokens expiram após 24h (86400 segundos)
   - Use o `refresh_token` para obter um novo `access_token`

5. **Frontend tentando acessar rota protegida sem token**
   - Todas as rotas (exceto /api/auth/*) requerem o header: `Authorization: Bearer <access_token>`

---

## 🧪 Como Testar Localmente

### Teste 1: Login
```bash
curl -X POST http://localhost:8001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"admin123"}'
```

### Teste 2: Obter Dados do Usuário Logado
```bash
# Substitua <TOKEN> com o access_token obtido no Teste 1
curl -X GET http://localhost:8001/api/auth/me \
  -H "Authorization: Bearer <TOKEN>"
```

### Teste 3: Refresh Token
```bash
curl -X POST http://localhost:8001/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"<REFRESH_TOKEN>"}'
```

---

## 📝 Configurações

As configurações estão em `backend/app/core/config.py`:

```python
admin_email: str = "admin@example.com"
admin_password: str = "admin123"
```

Se precisar mudar, edite essas linhas ou crie um arquivo `.env` na raiz do projeto.

---

## 🔐 Segurança

- Senhas são hashadas com **bcrypt**
- Tokens JWT usam algoritmo **HS256** com `settings.secret_key`
- Access token: **24 horas**
- Refresh token: **7 dias**

---

## ✅ Recomendações

1. Verifique o console do navegador quando tentar fazer login
2. Verifique se o endpoint está retornando token (use curl para testar)
3. Verifique se está enviando o token nos headers das requisições subsequentes
4. Se estiver em produção, mude a senha padrão via arquivo `.env`
