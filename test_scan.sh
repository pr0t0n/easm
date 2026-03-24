#!/bin/bash

# Script para testar o novo logging de progresso de scan
# Faz login, inicia um scan e monitora os logs com as melhorias

echo "🔍 Teste de Visibilidade de Scan - Script de CLI"
echo "================================================="
echo ""

# Configuração
TARGET="validcertificadora.com.br"
API="http://localhost:8000/api"

echo "📝 Etapa 1: Login na API"
echo "========================"

# Fazer login
TOKEN=$(curl -s -X POST "$API/auth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin@easm.local&password=admin123" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)

if [ -z "$TOKEN" ]; then
    echo "❌ Erro: Não foi possível fazer login"
    exit 1
fi

echo "✅ Login realizado"
echo "   Token: ${TOKEN:0:20}..."
echo ""

echo "🚀 Etapa 2: Iniciar novo scan"
echo "============================="

# Iniciar scan
RESPONSE=$(curl -s -X POST "$API/scans" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"target_query\": \"$TARGET\", \"mode\": \"single\", \"access_group_id\": null}")

SCAN_ID=$(echo "$RESPONSE" | grep -o '"id":[0-9]*' | head -1 | cut -d':' -f2)

if [ -z "$SCAN_ID" ]; then
    echo "❌ Erro ao iniciar scan"
    echo "Resposta: $RESPONSE"
    exit 1
fi

echo "✅ Scan iniciado"
echo "   Alvo: $TARGET"
echo "   ID: $SCAN_ID"
echo ""

echo "📊 Etapa 3: Monitorar logs com melhorias"
echo "======================================"
echo "Os logs com source='worker.progress_detail' mostram o progresso das missões"
echo ""

# Monitorar logs
LAST_LOG_ID=0
POLL_COUNT=0

while true; do
    RESPONSE=$(curl -s "$API/scans/$SCAN_ID/logs?limit=100" \
      -H "Authorization: Bearer $TOKEN")
    
    # Filtra logs novos e importantes
    IMPORTANT_SOURCES='"source":"worker.plan"|"source":"worker.progress_detail"|"source":"worker.summary"|"source":"worker"'
    
    LOGS=$(echo "$RESPONSE" | grep -E "$IMPORTANT_SOURCES" 2>/dev/null || echo "[]")
    NEW_LOGS=$(echo "$LOGS" | grep -o '"id":[0-9]*' | cut -d':' -f2)
    
    # Mostra apenas logs novos
    for LOG_ID in $NEW_LOGS; do
        if [ "$LOG_ID" -gt "$LAST_LOG_ID" ]; then
            LOG_SOURCE=$(echo "$RESPONSE" | grep "\"id\":$LOG_ID" | grep -o '"source":"[^"]*"' | cut -d'"' -f4)
            LOG_TIME=$(echo "$RESPONSE" | grep "\"id\":$LOG_ID" | grep -o '"created_at":"[^"]*"' | cut -d'"' -f4 | cut -d'T' -f2 | cut -d'.' -f1)
            LOG_MESSAGE=$(echo "$RESPONSE" | grep "\"id\":$LOG_ID" | grep -o '"message":"[^"]*"' | cut -d'"' -f4 | sed 's/\\n/\n  /g')
            
            case $LOG_SOURCE in
                "worker.plan")
                    echo -e "\033[36m[INFO] PLANO:$LOG_MESSAGE\033[0m"
                    ;;
                "worker.progress_detail")
                    echo -e "\033[94m[PROGRESSO]\n$LOG_MESSAGE\033[0m"
                    ;;
                "worker.summary")
                    echo -e "\033[92m[RESUMO]\n$LOG_MESSAGE\033[0m"
                    ;;
                "worker")
                    echo -e "  → $LOG_MESSAGE"
                    ;;
            esac
            
            LAST_LOG_ID=$LOG_ID
        fi
    done
    
    # Verifica status do scan
    STATUS=$(echo "$RESPONSE" | grep -o '"status":"[^"]*"' | head -1 | cut -d'"' -f4)
    
    if [ "$STATUS" = "completed" ]; then
        echo ""
        echo "🏁 Scan finalizado com sucesso!"
        break
    elif [ "$STATUS" = "failed" ] || [ "$STATUS" = "stopped" ]; then
        echo ""
        echo "⚠️  Scan finalizado com status: $STATUS"
        break
    fi
    
    POLL_COUNT=$((POLL_COUNT + 1))
    if [ $((POLL_COUNT % 3)) -eq 0 ]; then
        echo -n "."
    fi
    
    sleep 2
done

echo ""
echo "✅ Monitor encerrado"
