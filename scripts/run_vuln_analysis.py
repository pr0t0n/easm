#!/usr/bin/env python3
"""
Worker: Análise de Vulnerabilidade Completo
Executa 8 ferramentas de segurança disponíveis localmente contra um alvo
"""

import subprocess
import json
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

target = "65.valid.com"
output_dir = Path("/tmp/vuln_analysis")
output_dir.mkdir(exist_ok=True)

# Ferramentas disponíveis com timeout
tools_config = {
    "curl-headers": {
        "cmd": ["curl", "-I", "-sS", "--max-time", "20", f"http://{target}"],
        "timeout": 25,
        "description": "HTTP Headers Analysis",
    },
    "nikto": {
        "cmd": ["nikto", "-h", f"http://{target}", "-Tuning", "1234567890", "-o", "-"],
        "timeout": 240,
        "description": "Web Server Scanner",
    },
    "nuclei": {
        "cmd": ["nuclei", "--target", target, "-silent"],
        "timeout": 600,
        "description": "Template-based Vulnerability Scanner",
    },
    "sslscan": {
        "cmd": ["sslscan", "--no-colour", target],
        "timeout": 180,
        "description": "SSL/TLS Configuration Analysis",
    },
    "nmap-vulscan": {
        "cmd": ["nmap", "-sT", "-sV", "-A", "--top-ports", "50", "--script=/opt/homebrew/share/nmap/scripts/vulscan/vulscan.nse", "--script-args", "vulscandb=cve.csv", target],
        "timeout": 600,
        "description": "Network Vulnerability Scanning",
    },
    "sqlmap": {
        "cmd": ["sqlmap", "-u", f"http://{target}", "--batch", "--dbs"],
        "timeout": 300,
        "description": "SQL Injection Testing",
    },
    "ffuf": {
        "cmd": ["ffuf", "-u", f"http://{target}/FUZZ", "-w", "/usr/share/wordlists/dirb/common.txt", "-o", "-f"],
        "timeout": 120,
        "description": "Directory/Path Fuzzing",
    },
    "gobuster": {
        "cmd": ["gobuster", "dir", "-u", f"http://{target}", "-w", "/usr/share/wordlists/dirb/common.txt", "-q"],
        "timeout": 120,
        "description": "Directory Enumeration",
    },
}

print("=" * 100)
print(f"WORKER: Análise de Vulnerabilidade Completo")
print(f"ALVO: {target}")
print(f"DATA/HORA: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("=" * 100)

results = {
    "target": target,
    "timestamp": datetime.now().isoformat(),
    "execution_summary": {},
    "tool_results": {},
    "statistics": {},
}

print(f"\n📊 Executando {len(tools_config)} ferramentas de análise de vulnerabilidades...\n")

lock = threading.Lock()
completed_tools = [0]
total_tools = len(tools_config)

def execute_tool(tool_name, config):
    """Executa uma ferramenta e captura output"""
    try:
        print(f"⏳ [{tool_name}] Iniciando... {config['description']}")
        
        result = subprocess.run(
            config["cmd"],
            capture_output=True,
            text=True,
            timeout=config["timeout"]
        )
        
        output_file = output_dir / f"{tool_name}.txt"
        output_file.write_text(result.stdout if result.stdout else result.stderr)
        
        # Contar linhas de output
        line_count = len(result.stdout.strip().split('\n')) if result.stdout else 0
        
        tool_result = {
            "status": "success",
            "return_code": result.returncode,
            "output_lines": line_count,
            "file": str(output_file),
            "execution_time": config["timeout"],  # aproximado
        }
        
        if result.returncode == 0:
            status_icon = "✅"
        else:
            status_icon = "⚠️"
            tool_result["status"] = "completed_with_warnings"
        
        with lock:
            completed_tools[0] += 1
            progress = completed_tools[0]
        
        print(f"{status_icon} [{progress}/{total_tools}] {tool_name:20} → {line_count:5} linhas | Return code: {result.returncode}")
        
        return tool_name, tool_result
        
    except subprocess.TimeoutExpired:
        with lock:
            completed_tools[0] += 1
            progress = completed_tools[0]
        
        print(f"⏱️  [{progress}/{total_tools}] {tool_name:20} → TIMEOUT após {config['timeout']}s")
        return tool_name, {
            "status": "timeout",
            "output_lines": 0,
            "timeout_seconds": config["timeout"],
        }
    
    except FileNotFoundError:
        with lock:
            completed_tools[0] += 1
            progress = completed_tools[0]
        
        print(f"❌ [{progress}/{total_tools}] {tool_name:20} → NÃO INSTALADO")
        return tool_name, {
            "status": "not_installed",
            "output_lines": 0,
        }
    
    except Exception as e:
        with lock:
            completed_tools[0] += 1
            progress = completed_tools[0]
        
        print(f"❌ [{progress}/{total_tools}] {tool_name:20} → ERRO: {str(e)[:50]}")
        return tool_name, {
            "status": "error",
            "error": str(e),
        }

# Executar ferramentas em paralelo com ThreadPoolExecutor
print("Iniciando execuções paralelas...\n")

with ThreadPoolExecutor(max_workers=4) as executor:
    future_to_tool = {
        executor.submit(execute_tool, tool_name, config): tool_name 
        for tool_name, config in tools_config.items()
    }
    
    for future in as_completed(future_to_tool):
        tool_name, result = future.result()
        results["tool_results"][tool_name] = result

print("\n" + "=" * 100)
print("RESUMO DA EXECUÇÃO")
print("=" * 100)

# Estatísticas
successful = sum(1 for r in results["tool_results"].values() if r["status"] == "success")
completed = sum(1 for r in results["tool_results"].values() if r["status"] in ["success", "completed_with_warnings"])
timeouts = sum(1 for r in results["tool_results"].values() if r["status"] == "timeout")
not_installed = sum(1 for r in results["tool_results"].values() if r["status"] == "not_installed")
errors = sum(1 for r in results["tool_results"].values() if r["status"] == "error")
total_lines = sum(r.get("output_lines", 0) for r in results["tool_results"].values())

results["statistics"] = {
    "total_tools": len(tools_config),
    "successful": successful,
    "completed": completed,
    "timeouts": timeouts,
    "not_installed": not_installed,
    "errors": errors,
    "total_output_lines": total_lines,
}

print(f"\n✅ Conclusão bem-sucedida: {successful}/{total_tools}")
print(f"⚠️  Completadas com warnings: {completed - successful}")
print(f"⏱️  Timeouts: {timeouts}")
print(f"❌ Não instaladas: {not_installed}")
print(f"❌ Erros: {errors}")

print(f"\n📊 Dados Coletados:")
print(f"   • Total de linhas de output: {total_lines:,}")
print(f"   • Diretório de resultados: {output_dir}")

# Detalhe por ferramenta
print(f"\n📋 Detalhe da Execução:\n")
print(f"{'Tool':<20} {'Status':<20} {'Lines':<10}")
print("-" * 50)

for tool_name in sorted(results["tool_results"].keys()):
    result = results["tool_results"][tool_name]
    status = result.get("status", "unknown")
    lines = result.get("output_lines", 0)
    
    status_display = {
        "success": "✅ Sucesso",
        "completed_with_warnings": "⚠️  Com warnings",
        "timeout": "⏱️  Timeout",
        "not_installed": "❌ Não instalado",
        "error": "❌ Erro",
    }
    
    print(f"{tool_name:<20} {status_display.get(status, status):<20} {lines:<10}")

# Salvar resultado em JSON
results_file = output_dir / "execution_results.json"
with open(results_file, "w") as f:
    json.dump(results, f, indent=2)

print(f"\n✅ Resultados salvos em: {results_file}")

# Mostrar sample de cada tool
print(f"\n" + "=" * 100)
print("SAMPLE DE ACHADOS POR FERRAMENTA")
print("=" * 100)

for tool_name in sorted(tools_config.keys()):
    output_file = output_dir / f"{tool_name}.txt"
    if output_file.exists():
        content = output_file.read_text()
        lines = content.strip().split('\n')
        print(f"\n🔍 {tool_name.upper()}")
        print(f"   Total de linhas: {len(lines)}")
        if lines:
            print(f"   Primeiras 3 linhas:")
            for line in lines[:3]:
                if line.strip():
                    preview = line[:90] + "..." if len(line) > 90 else line
                    print(f"      • {preview}")

print(f"\n" + "=" * 100)
print("✅ EXECUÇÃO COMPLETA")
print("=" * 100)
