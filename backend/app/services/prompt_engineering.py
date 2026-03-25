"""
Prompt Engineering for FAIR to Financial Risk Quantification

Transforma métricas técnicas FAIR em linguagem executiva com
estimativa de $ em risco baseado em custo de data breach por setor.

Fontes:
- IBM Cost of Data Breach 2023 ($4.45M avg, $185/record)
- Ponemon Incident Response Costs ($11.6M avg incident)
- FAIR V2.3 Framework quantification guidelines
"""

from datetime import datetime
from typing import Dict, List, Any, Optional


# ──────────────────────────────────────────────────────────────────────────────
# FINANCIAL IMPACT MODELS (Custo de Data Breach por Setor)
# ──────────────────────────────────────────────────────────────────────────────


SECTOR_BREACH_COSTS = {
    # Cost USD per record exposed
    "financial_services": {
        "cost_per_record": 250,
        "avg_records_exposed": 150000,
        "incident_response_hours": 500,
        "hourly_rate": 1200,  # Security consultants
    },
    "healthcare": {
        "cost_per_record": 610,  # Highest (patient PHI)
        "avg_records_exposed": 100000,
        "incident_response_hours": 800,
        "hourly_rate": 1500,
    },
    "technology": {
        "cost_per_record": 180,
        "avg_records_exposed": 500000,  # Larger user base
        "incident_response_hours": 400,
        "hourly_rate": 1200,
    },
    "manufacturing": {
        "cost_per_record": 195,
        "avg_records_exposed": 80000,
        "incident_response_hours": 300,
        "hourly_rate": 1000,
    },
    "retail": {
        "cost_per_record": 140,
        "avg_records_exposed": 2000000,  # PCI compliance
        "incident_response_hours": 350,
        "hourly_rate": 900,
    },
    "government": {
        "cost_per_record": 210,
        "avg_records_exposed": 500000,
        "incident_response_hours": 600,
        "hourly_rate": 1100,
    },
    "default": {
        "cost_per_record": 185,
        "avg_records_exposed": 200000,
        "incident_response_hours": 400,
        "hourly_rate": 1100,
    },
}

# FAIR Magnitude of Loss Estimations (when breach occurs)
FAIR_MAGNITUDE_MULTIPLIERS = {
    "data_loss": 0.6,  # Probabilidade de perda de dados em breach
    "business_disruption": 0.3,  # Downtime custo (hourly rate × horas)
    "reputational_damage": 0.2,  # Churn de clientes, stock price drop
    "regulatory_fines": 0.4,  # GDPR, HIPAA, PCI-DSS penalties
}


class FinancialRiskQuantifier:
    """Quantifica risco técnico em $ monetário"""

    @staticmethod
    def calculate_potential_loss(
        sector: str,
        severity: str,
        asset_type: str,
        vulnerability_age_days: int,
        is_crown_jewel: bool = False,
    ) -> Dict[str, float]:
        """
        Calcula Potential Loss em $ para uma vulnerabilidade

        Args:
            sector: setor (financial_services, healthcare, etc)
            severity: critical, high, medium, low
            asset_type: web, database, login, ssh, etc
            vulnerability_age_days: dias desde a descoberta
            is_crown_jewel: se é ativo crítico

        Returns:
            {
                "base_loss": 500000,
                "loss_with_age_multiplier": 750000,  # AGE aumenta perda potencial
                "crown_jewel_multipler": 2.0 or 1.0,
                "total_potential_loss": 750000,
            }
        """
        sector_config = SECTOR_BREACH_COSTS.get(sector, SECTOR_BREACH_COSTS["default"])

        # Severity multiplier (CVSS to loss percentage)
        severity_to_loss_pct = {
            "critical": 0.80,  # 80% das records podem se expostas
            "high": 0.50,
            "medium": 0.20,
            "low": 0.05,
            "info": 0.01,
        }
        loss_pct = severity_to_loss_pct.get(severity, 0.20)

        # Base potential loss
        avg_records = sector_config["avg_records_exposed"]
        cost_per_record = sector_config["cost_per_record"]
        base_loss = avg_records * cost_per_record * loss_pct

        # AGE multiplier (vulnerabilidade antiga = mais tempo para ser explorada)
        # 1 + log10(days_open + 1) = tempo exposto aumenta risco
        age_multiplier = 1.0 + (vulnerability_age_days / 100.0)  # 1 pt por 100 dias

        incident_response_cost = (
            sector_config["incident_response_hours"] * sector_config["hourly_rate"]
        )

        # Asset type multiplier
        asset_multipliers = {
            "database": 1.5,  # Muito impacto
            "login": 1.3,  # Acesso autenticado
            "web": 1.0,
            "ssh": 1.2,
            "api": 1.1,
        }
        asset_mult = asset_multipliers.get(asset_type, 1.0)

        # Crown jewel (assetcrítico aumenta risco)
        crown_jewel_mult = 3.0 if is_crown_jewel else 1.0

        loss_with_age = base_loss * age_multiplier + incident_response_cost
        total_loss = loss_with_age * asset_mult * crown_jewel_mult

        return {
            "base_loss": round(base_loss, 2),
            "loss_with_age_multiplier": round(loss_with_age, 2),
            "asset_type_multiplier": asset_mult,
            "crown_jewel_multiplier": crown_jewel_mult,
            "total_potential_loss": round(min(total_loss, 50000000), 2),  # Cap at $50M
        }

    @staticmethod
    def estimate_threat_event_frequency(
        severity: str,
        vulnerability_age_days: int,
        threat_intelligence: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, float]:
        """
        Estima Threat Event Frequency (TEF) - probabilidade exploração/ano

        FAIR Framework:
        TEF = % exploits públicos × % vulnerability exposure × % threat agent capability

        Args:
            severity: CVSS severity (correlaciona com % exploits)
            vulnerability_age_days: dias desde descoberta
            threat_intelligence: threat context (e.g., CVE em exploit kits)

        Returns:
            {
                "annual_exploit_probability": 0.25,  # 25% chance/ano
                "tef_factor": 0.25,  # Número FAIR
            }
        """
        # Severity → exploitation probability
        sev_to_exploit_prob = {
            "critical": 0.70,  # Críticas são rapidamente exploradas
            "high": 0.40,
            "medium": 0.15,
            "low": 0.05,
            "info": 0.01,
        }
        base_prob = sev_to_exploit_prob.get(severity, 0.15)

        # Age factor (vulnerabilidade antiga = maior probabilidade)
        # 0% chance no dia 0, crescente até 100% após 180 dias
        age_factor = min(1.0, vulnerability_age_days / 180.0)

        # Threat intelligence multiplier
        ti_multiplier = 1.0
        if threat_intelligence:
            if threat_intelligence.get("in_exploit_kits"):
                ti_multiplier = 2.5  # Já em active exploitation
            elif threat_intelligence.get("has_public_poc"):
                ti_multiplier = 1.8
            elif threat_intelligence.get("cisa_known_exploited"):
                ti_multiplier = 2.0

        annual_probability = base_prob * (1.0 + age_factor) * ti_multiplier
        tef_factor = min(1.0, annual_probability)

        return {
            "annual_exploit_probability": round(tef_factor, 3),
            "severity_component": base_prob,
            "age_component": age_factor,
            "threat_intel_multiplier": ti_multiplier,
            "tef_factor": round(tef_factor, 3),
        }


# ──────────────────────────────────────────────────────────────────────────────
# NARRATIVE TEMPLATES (Executiva Language)
# ──────────────────────────────────────────────────────────────────────────────


class ExecutiveNarrativeGenerator:
    """Gera narrativa executiva FAIR→$"""

    @staticmethod
    def generate_fair_narrative(
        easm_rating: float,
        easm_grade: str,
        potential_loss: float,
        tef_probability: float,
        open_critical_count: int,
        oldest_critical_age_days: int,
        sector: str,
    ) -> str:
        """
        Gera narrativa de 3-5 parágrafos para CISO/Executivos

        Exemplo:
        "Sua postura EASM atual é de 72 (Grau C), expondo ~$1.2M em risco potencial.
        O principal driver é a presença de 5 vulnerabilidades críticas não remediadas há
        > 30 dias, cada uma com ~25% de chance de exploração anual (CVSS 9.8, sem patches).
        Se uma destas for explorada, os custos de resposta + perda de dados podem chegar
        a $850K. Recomendação: Priorice os 5 críticos para remediação em <7 dias."
        """
        narrativa = f"""
**Postura EASM: {easm_grade} (Score {easm_rating}/100)**

Sua organização enfrenta **${potential_loss:,.0f}** em risco potencial de exposição,
impulsionado por {open_critical_count} vulnerabilidade(idades) crítica(s) aberta(s) há mais
de {oldest_critical_age_days} dias.

Cada uma dessas falhas tem **~{tef_probability*100:.0f}% de probabilidade anual de
exploração ativa**, acelerada pelo tempo (Age Factor FAIR). No setor {sector}, uma
violação média custa ${SECTOR_BREACH_COSTS.get(sector, SECTOR_BREACH_COSTS["default"])["cost_per_record"]} por registro exposto.

**Ação Imediata Recomendada:**
- Priorizar remediação dos {min(5, open_critical_count)} critérios em <7 dias
- Aplicar Mitigação Compensadora (WAF, Isolamento de Rede) até patch
- Revisar Logs de Acesso para indicadores de exploração

"""
        return narrativa.strip()

    @staticmethod
    def generate_financial_impact_summary(
        findings: List[Dict[str, Any]],
        sector: str,
    ) -> Dict[str, Any]:
        """
        Sumariza impacto financeiro agregado de um conjunto de findings

        findings: [
            {
                "severity": "critical",
                "title": "SQL Injection",
                "asset_type": "database",
                "days_open": 10,
                "is_crown_jewel": True,
            },
            ...
        ]
        """
        total_potential_loss = 0.0
        weighted_tef = 0.0
        critical_count = 0

        for finding in findings:
            loss = FinancialRiskQuantifier.calculate_potential_loss(
                sector=sector,
                severity=finding.get("severity", "low"),
                asset_type=finding.get("asset_type", "web"),
                vulnerability_age_days=finding.get("days_open", 0),
                is_crown_jewel=finding.get("is_crown_jewel", False),
            )
            
            tef = FinancialRiskQuantifier.estimate_threat_event_frequency(
                severity=finding.get("severity", "low"),
                vulnerability_age_days=finding.get("days_open", 0),
            )

            total_potential_loss += loss["total_potential_loss"]
            weighted_tef += tef["tef_factor"]
            
            if finding.get("severity") == "critical":
                critical_count += 1

        avg_tef = weighted_tef / max(1, len(findings))

        return {
            "total_potential_loss": round(total_potential_loss, 2),
            "weighted_threat_frequency": round(avg_tef, 3),
            "critical_findings":critical_count,
            "expected_annual_loss": round(total_potential_loss * avg_tef, 2),
            "narrative": f"""
Com base em métricas FAIR de mercado (Ponemon 2023, IBM Cost of Breach),
sua organização tem **${total_potential_loss:,.0f}** em exposição potencial,
com **{avg_tef*100:.1f}%** de possibilidade de incidente em 12 meses.
Isso resulta em **${total_potential_loss * avg_tef:,.0f}** de perda esperada anual
se não mitigado.
            """.strip(),
        }


# ──────────────────────────────────────────────────────────────────────────────
# PROMPT TEMPLATES para LLM (Claude, GPT, Ollama)
# ──────────────────────────────────────────────────────────────────────────────


EXECUTIVE_PROMPT_TEMPLATE = """
You are a cybersecurity risk advisor. Given the following EASM data, generate a concise 
executive summary (2-3 paragraphs) explaining the financial risk in business terms.

**EASM Rating Data:**
- Current Score: {easm_rating}/100 (Grade: {easm_grade})
- Potential Financial Loss: ${potential_loss:,.0f}
- Open Critical Vulnerabilities: {critical_count}
- Oldest Critical Vulnerability: {oldest_critical_age} days open
- Sector: {sector}
- Remediation Velocity: {remediation_velocity}% per week

**Key Findings:**
{key_findings}

Generate an executive narrative that:
1. Translates technical risk to business impact ($, regulatory risk, operational downtime)
2. Explains time urgency (age of vulnerabilities, exploitation probability)
3. Provides 2-3 immediate recommended actions
4. Mentions regulatory impact if relevant (GDPR, HIPAA, PCI-DSS)

Keep language accessible to non-technical stakeholders (CFO, Board level).
"""

CISO_PROMPT_TEMPLATE = """
You are a CISO advising on security posture. Based on the following EASM assessment,
provide a 3-paragraph technical narrative including remediation priorities.

**EASM Metrics:**
- FAIR Decomposition:
  - Perimeter Resilience: {perimeter_score}/100
  - Patching Hygiene: {patching_score}/100
  - OSINT Exposure: {osint_score}/100
- Remediation Velocity: {velocity}/week (Trend: {trend})
- Forecast 30-day Rating: {forecast_30d}

**Top Risks (by RA score):**
{top_risks}

Provide:
1. Current posture assessment (what's working, what isn't)
2. Root cause analysis (systemic issues vs. one-offs)
3. 90-day remediation roadmap with Phase 1 (week 1-2) priorities
"""
