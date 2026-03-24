#!/usr/bin/env python3
"""
Script de teste para validar as melhorias de visibilidade de scan.
Inicia um novo scan e monitora os novos logs de progresso.
"""

import requests
import json
import time
import sys
from datetime import datetime

BASE_URL = "http://localhost:8000/api"

def login():
    """Faz login na API (padrão de teste)"""
    response = requests.post(
        f"{BASE_URL}/auth/token",
        data={"username": "admin@easm.local", "password": "admin123"}
    )
    if response.status_code != 200:
        print(f"❌ Erro ao fazer login: {response.status_code}")
        print(response.text)
        return None
    return response.json()["access_token"]

def start_scan(token: str, target: str):
    """Inicia um novo scan"""
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.post(
        f"{BASE_URL}/scans/start",
        headers=headers,
        json={"target": target, "mode": "single", "compliance_checked": True}
    )
    if response.status_code not in [200, 201]:
        print(f"❌ Erro ao iniciar scan: {response.status_code}")
        print(response.text)
        return None
    return response.json()["scan_id"]

def get_scan_logs(token: str, scan_id: int, limit: int = 50):
    """Obtém logs do scan"""
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(
        f"{BASE_URL}/scans/{scan_id}/logs?limit={limit}",
        headers=headers
    )
    if response.status_code != 200:
        return []
    return response.json()

def print_new_logs(logs: list, seen_ids: set):
    """Imprime apenas logs novos"""
    new_logs = []
    for log in logs:
        if log["id"] not in seen_ids:
            seen_ids.add(log["id"])
            new_logs.append(log)
    
    # Ordena por tempo
    new_logs.sort(key=lambda x: x["created_at"])
    
    colors = {
        "worker.plan": "\033[36m",        # Cyan
        "worker": "\033[92m",              # Green
        "worker.progress": "\033[93m",     # Yellow
        "worker.progress_detail": "\033[94m",  # Blue   
        "worker.summary": "\033[92m",      # Green bold
        "graph": "\033[95m",               # Magenta
        "worker.retry": "\033[91m",        # Red
    }
    reset = "\033[0m"
    
    for log in new_logs:
        source = log.get("source", "unknown")
        level = log.get("level", "INFO")
        message = log.get("message", "")
        created_at = log.get("created_at", "")
        
        color = colors.get(source, "\033[37m")
        
        # Format time
        try:
            # Parse ISO format and extract time part
            time_str = created_at.split("T")[1].split(".")[0]
        except:
            time_str = created_at[:19]
        
        # Handle multi-line messages
        lines = message.split("\n")
        print(f"{color}[{time_str}] {source:25} | {lines[0]}{reset}")
        for line in lines[1:]:
            print(f"{color}                      | {line}{reset}")
    
    return len(new_logs)

def main():
    print("🔍 Teste de Visibilidade de Scan Enhanced\n")
    
    # Login
    print("📝 Fazendo login...")
    token = login()
    if not token:
        sys.exit(1)
    print("✅ Login realizado\n")
    
    # Iniciar scan
    target = "validcertificadora.com.br"
    print(f"🚀 Iniciando scan do alvo: {target}")
    scan_id = start_scan(token, target)
    if not scan_id:
        sys.exit(1)
    print(f"✅ Scan iniciado (ID: {scan_id})\n")
    
    # Monitorar logs
    print("📊 Monitorando logs do scan (pressione Ctrl+C para parar)...\n")
    print("=" * 100)
    
    seen_ids = set()
    poll_count = 0
    last_status = None
    
    try:
        while True:
            logs = get_scan_logs(token, scan_id, limit=100)
            new_count = print_new_logs(logs, seen_ids)
            
            # Check status
            if logs:
                latest = logs[-1] if isinstance(logs, list) and logs else None
                if isinstance(latest, dict):
                    status = latest.get("status")
                    if status and status != last_status:
                        last_status = status
                        print(f"\n⚠️  Status: {status}\n")
                        if status in ["completed", "failed", "stopped"]:
                            print("🏁 Scan finalizado!")
                            break
            
            poll_count += 1
            if poll_count % 3 == 0:  # A cada ~6 segundos, mostra ponto
                print(".", end="", flush=True)
            
            time.sleep(2)  # Poll a cada 2 segundos
            
    except KeyboardInterrupt:
        print("\n\n⛔ Monitoramento interrompido pelo usuário")

if __name__ == "__main__":
    main()
