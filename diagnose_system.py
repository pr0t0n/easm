#!/usr/bin/env python3
"""Script de diagnóstico para validar o fluxo de ferramentas e aprendizado."""

import os
import sys
import requests
from datetime import datetime

# Adicionar o diretório backend ao path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

# Configurar DATABASE_URL para sqlite se não estiver definido
if 'DATABASE_URL' not in os.environ:
    os.environ['DATABASE_URL'] = 'sqlite:///./test_learning.db'

def check_ollama():
    """Verifica se Ollama está disponível."""
    try:
        ollama_url = os.getenv("OLLAMA_BASE_URL", "http://ollama:11434")
        response = requests.get(f"{ollama_url}/api/tags", timeout=5)
        if response.status_code == 200:
            models = response.json().get("models", [])
            print(f"✅ Ollama disponível. Modelos: {[m['name'] for m in models]}")
            return True
        else:
            print(f"❌ Ollama respondeu com status {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Ollama não disponível: {e}")
        return False

def check_kali_runner():
    """Verifica se o Kali runner está disponível."""
    try:
        kali_url = os.getenv("KALI_RUNNER_URL", "http://kali_runner:8088")
        response = requests.get(f"{kali_url}/healthz", timeout=5)
        if response.status_code == 200:
            print("✅ Kali runner disponível")
            return True
        else:
            print(f"❌ Kali runner respondeu com status {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Kali runner não disponível: {e}")
        return False

def check_learning():
    """Verifica se há aprendizados aceitos no banco."""
    try:
        from app.db.session import SessionLocal
        from app.models.models import VulnerabilityLearning

        db = SessionLocal()
        count = db.query(VulnerabilityLearning).filter(VulnerabilityLearning.status == "accepted").count()
        db.close()

        if count > 0:
            print(f"✅ {count} aprendizados aceitos encontrados")
            return True
        else:
            print("❌ Nenhum aprendizado aceito encontrado")
            return False
    except Exception as e:
        print(f"❌ Erro ao verificar aprendizado: {e}")
        return False

def test_supervisor_fallback():
    """Testa o fallback do supervisor."""
    try:
        from app.agents.supervisor_runtime import decide_next_technique

        playbook = {
            "title": "Test playbook",
            "techniques": [
                {"name": "test_technique", "objective": "test objective"}
            ]
        }
        execution_context = {
            "phase": "RECONNAISSANCE",
            "target": "example.com"
        }
        tool_catalog = ["nmap", "subfinder"]

        # Forçar fallback definindo timeout muito baixo
        decision = decide_next_technique(
            playbook=playbook,
            execution_context=execution_context,
            tool_catalog=tool_catalog,
            timeout=0.001  # Timeout muito baixo para forçar fallback
        )

        if decision and decision.get("execution_decision") == "proceed":
            print("✅ Supervisor fallback funcionando")
            print(f"   Técnica selecionada: {decision.get('selected_technique', {}).get('name')}")
            return True
        else:
            print("❌ Supervisor fallback falhou")
            return False
    except Exception as e:
        print(f"❌ Erro no teste do supervisor: {e}")
        return False

def main():
    print("🔍 Diagnóstico do Sistema EASM")
    print("=" * 50)

    ollama_ok = check_ollama()
    kali_ok = check_kali_runner()
    learning_ok = check_learning()
    supervisor_ok = test_supervisor_fallback()

    print("\n📊 Resumo:")
    print(f"  Ollama: {'✅' if ollama_ok else '❌'}")
    print(f"  Kali Runner: {'✅' if kali_ok else '❌'}")
    print(f"  Aprendizado: {'✅' if learning_ok else '❌'}")
    print(f"  Supervisor: {'✅' if supervisor_ok else '❌'}")

    if not ollama_ok:
        print("\n💡 Recomendação: Inicie o Ollama ou configure LLM alternativo")
    if not kali_ok:
        print("\n💡 Recomendação: Inicie o Kali runner com docker-compose")
    if not learning_ok:
        print("\n💡 Recomendação: Execute populate_learning.py para adicionar dados de teste")
    if not supervisor_ok:
        print("\n💡 Recomendação: Verifique configuração do supervisor")

if __name__ == "__main__":
    main()