#!/usr/bin/env python3
"""Script para popular o banco com aprendizados aceitos para teste."""

import os
import sys
from datetime import datetime

# Adicionar o diretório backend ao path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

# Configurar DATABASE_URL para sqlite se não estiver definido
if 'DATABASE_URL' not in os.environ:
    os.environ['DATABASE_URL'] = 'sqlite:///./test_learning.db'

from app.db.session import SessionLocal
from app.models.models import VulnerabilityLearning

def populate_learning():
    """Popula o banco com exemplos de aprendizado aceito."""
    db = SessionLocal()
    try:
        # Verificar se já existem aprendizados
        existing = db.query(VulnerabilityLearning).filter(VulnerabilityLearning.status == "accepted").count()
        if existing > 0:
            print(f"Já existem {existing} aprendizados aceitos. Pulando população.")
            return

        # Criar exemplos de aprendizado
        learnings = [
            {
                "title": "SQL Injection em formulários de login",
                "vulnerability_type": "SQL Injection",
                "summary": "Ataque de injeção SQL em endpoints de autenticação",
                "status": "accepted",
                "accepted_at": datetime.utcnow(),
                "affected_phases": ["WEAPONIZATION", "EXPLOITATION"],
                "affected_skills": ["vuln-auth-bypass"],
                "recommended_tools": ["sqlmap", "ffuf"],
                "learned_mission": "Testar injeção SQL em formulários de login usando payloads seguros",
                "raw_extraction": {
                    "risk_score_hint": "high",
                    "evidence_signals": ["SQL syntax error", "database error messages"],
                    "safe_validation_steps": ["Test with single quote", "Use sqlmap with --safe-url"],
                }
            },
            {
                "title": "XSS em campos de comentário",
                "vulnerability_type": "Cross-Site Scripting",
                "summary": "XSS refletido em campos de entrada de usuário",
                "status": "accepted",
                "accepted_at": datetime.utcnow(),
                "affected_phases": ["WEAPONIZATION"],
                "affected_skills": ["vuln-web-injection"],
                "recommended_tools": ["dalfox", "ffuf"],
                "learned_mission": "Validar XSS em campos de entrada usando payloads não-destrutivos",
                "raw_extraction": {
                    "risk_score_hint": "medium",
                    "evidence_signals": ["<script> tags in response", "alert() execution"],
                    "safe_validation_steps": ["Test with <script>alert(1)</script>", "Use dalfox with --blind"],
                }
            },
            {
                "title": "Subdomain enumeration passiva",
                "vulnerability_type": "Information Disclosure",
                "summary": "Descoberta de subdomínios através de fontes passivas",
                "status": "accepted",
                "accepted_at": datetime.utcnow(),
                "affected_phases": ["RECONNAISSANCE"],
                "affected_skills": ["recon-subdomain-enum"],
                "recommended_tools": ["subfinder", "amass"],
                "learned_mission": "Enumerar subdomínios usando fontes passivas sem escaneamento ativo",
                "raw_extraction": {
                    "risk_score_hint": "low",
                    "evidence_signals": ["new subdomains found", "DNS records"],
                    "safe_validation_steps": ["Use subfinder -silent", "Check DNS resolution"],
                }
            }
        ]

        for learning_data in learnings:
            learning = VulnerabilityLearning(**learning_data)
            db.add(learning)

        db.commit()
        print(f"Populado {len(learnings)} aprendizados aceitos para teste.")

    except Exception as e:
        print(f"Erro ao popular aprendizado: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    populate_learning()