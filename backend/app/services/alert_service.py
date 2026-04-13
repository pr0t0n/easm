"""
EASM Alerts Service - Webhooks, Triggers, Posture Deviation Detection

Monitora gatilhos:
1. Rating Drop >10 pontos em 24h
2. Crown Jewel Age exceeds threshold (7 dias) com crítica
3. New Critical vulnerability detected
4. Zero remediation for 30 dias
"""

import asyncio
import json
import logging
import smtplib
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Callable
from enum import Enum
from email.message import EmailMessage

import httpx
from sqlalchemy import and_
from sqlalchemy.orm import Session

from app.models.models import (
    EASMAlert, EASMAlertRule, Asset, AssetRatingHistory,
    Vulnerability, User,
)
from app.services.risk_service import compute_posture_deviation
from app.core.config import settings


logger = logging.getLogger(__name__)


class AlertType(str, Enum):
    """Tipos de alertas EASM"""
    RATING_DROP = "rating_drop"  # Rating caiu >10 pts em 24h
    CROWN_JEWEL_AGE = "crown_jewel_age"  # Asset crítico com vulnidade antiga
    CRITICAL_SPIKE = "critical_spike"  # Novo crítico descoberto
    ZERO_REMEDIATION = "zero_remediation"  # Nenhuma remediação em 30 dias
    VELOCITY_DEGRADATION = "velocity_degradation"  # Velocidade caiu
    PILLAR_THRESHOLD = "pillar_threshold"  # Pillar FAIR abaixo de 50%


class AlertSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"


# ──────────────────────────────────────────────────────────────────────────────
# ALERT DETECTION LOGIC
# ──────────────────────────────────────────────────────────────────────────────


class AlertDetector:
    """Detecta condições que disparam alertas"""

    @staticmethod
    def detect_rating_drop(
        db: Session,
        owner_id: int,
        current_rating: float,
        previous_rating: float,
        asset_id: Optional[int] = None,
        threshold_points: float = 10.0,
        period_hours: int = 24,
    ) -> Optional[Dict[str, Any]]:
        """
        Detecta queda de rating >10 pts em período

        Retorna alert config ou None
        """
        deviation = AlertDetector._compute_posture_deviation(current_rating, previous_rating, period_hours=period_hours)

        threshold = max(0.1, float(threshold_points))
        drop_points = abs(float(deviation["deviation"]))

        if deviation["deviation"] < 0 and drop_points >= threshold:
            return {
                "type": AlertType.RATING_DROP,
                "severity": AlertSeverity.CRITICAL,
                "title": f"Rating caiu {drop_points} pontos",
                "description": f"Postura de segurança degradou de {previous_rating:.1f} para {current_rating:.1f}. Causa: {deviation['cause']}",
                "trigger_value": drop_points,
                "threshold_value": threshold,
            }
        return None

    @staticmethod
    def detect_crown_jewel_age(
        db: Session,
        owner_id: int,
        asset_id: int,
        critical_age_threshold_days: int = 7,
    ) -> Optional[Dict[str, Any]]:
        """
        Detecta se asset crítico tem crítica aberta há >threshold dias

        Gatilho: criticality_score >= 80 E crítica aberta há >7 dias
        """
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if not asset or asset.criticality_score < 80:
            return None

        # Check for old critical vuln
        old_critical = (
            db.query(Vulnerability)
            .filter(
                Vulnerability.asset_id == asset_id,
                Vulnerability.severity == "critical",
                Vulnerability.remediated_at == None,
            )
            .all()
        )

        if not old_critical:
            return None

        oldest = min((v.first_detected for v in old_critical), default=datetime.now(timezone.utc))
        age_days = (datetime.now(timezone.utc) - oldest).days

        if age_days >= critical_age_threshold_days:
            return {
                "type": AlertType.CROWN_JEWEL_AGE,
                "severity": AlertSeverity.CRITICAL,
                "title": f"Asset crítico '{asset.domain_or_ip}' com vulnerabilidade crítica não remediada há {age_days} dias",
                "description": f"Criticality: {asset.criticality_score}/100. Falhas críticas: {len(old_critical)}. Mais antiga: {age_days} dias.",
                "trigger_value": age_days,
                "threshold_value": critical_age_threshold_days,
            }
        return None

    @staticmethod
    def detect_critical_spike(
        db: Session,
        owner_id: int,
        new_critical_count: int,
        lookback_hours: int = 24,
    ) -> Optional[Dict[str, Any]]:
        """Detecta novas vulnerabilidades críticas descobertas recentemente"""
        if new_critical_count < 1:
            return None

        return {
            "type": AlertType.CRITICAL_SPIKE,
            "severity": AlertSeverity.HIGH if new_critical_count == 1 else AlertSeverity.CRITICAL,
            "title": f"{new_critical_count} nova(s) vulnerabilidade(s) crítica(s) descoberta(s)",
            "description": f"{new_critical_count} falha(s) de severidade crítica foi/foram detectada(s) nas últimas {lookback_hours} horas.",
            "trigger_value": new_critical_count,
            "threshold_value": 1.0,
        }

    @staticmethod
    def detect_zero_remediation(
        db: Session,
        owner_id: int,
        asset_id: Optional[int] = None,
        days: int = 30,
    ) -> Optional[Dict[str, Any]]:
        """Detecta se nenhuma remediação ocorreu em N dias"""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        query = (
            db.query(Vulnerability)
            .filter(Vulnerability.remediated_at < cutoff)
        )

        if asset_id:
            query = query.filter(Vulnerability.asset_id == asset_id)

        recent_remediation = (
            db.query(Vulnerability)
            .filter(
                Vulnerability.remediated_at >= cutoff,
            )
        )

        if asset_id:
            recent_remediation = recent_remediation.filter(Vulnerability.asset_id == asset_id)

        recent_count = recent_remediation.count()

        if recent_count == 0:
            open_vulns = query.filter(Vulnerability.remediated_at == None).count()
            if open_vulns > 0:
                return {
                    "type": AlertType.ZERO_REMEDIATION,
                    "severity": AlertSeverity.HIGH,
                    "title": f"Nenhuma remediação nos últimos {days} dias",
                    "description": f"Nenhuma vulnerabilidade foi remediada nos últimos {days} dias. {open_vulns} ainda estão abertas.",
                    "trigger_value": 0.0,
                    "threshold_value": 1.0,
                }
        return None

    @staticmethod
    def _compute_posture_deviation(current: float, previous: float, period_hours: int = 24) -> Dict[str, Any]:
        """Utilitário: compute_posture_deviation"""
        return compute_posture_deviation(current, previous, period_hours=period_hours)


class AlertAction:
    """Executa ação de alerta (webhook, email, etc)"""

    @staticmethod
    async def trigger_webhook(
        webhook_url: str,
        alert_data: Dict[str, Any],
        timeout_seconds: int = 5,
    ) -> bool:
        """Envia alerta para webhook externo (Slack, PagerDuty, SIEM)"""
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_type": alert_data.get("type"),
            "severity": alert_data.get("severity"),
            "title": alert_data.get("title"),
            "description": alert_data.get("description"),
            "trigger_value": alert_data.get("trigger_value"),
            "threshold_value": alert_data.get("threshold_value"),
        }

        try:
            async with httpx.AsyncClient(timeout=timeout_seconds) as client:
                resp = await client.post(webhook_url, json=payload)
                success = resp.status_code in (200, 201, 202, 204)
                logger.info(f"[Alert Webhook] {webhook_url}: {resp.status_code} {'✓' if success else '✗'}")
                return success
        except Exception as e:
            logger.error(f"[Alert Webhook] Erro ao enviar para {webhook_url}: {e}")
            return False

    @staticmethod
    async def send_email(
        recipient: str,
        subject: str,
        body: str,
    ) -> bool:
        """Envia alerta por email via SMTP quando configurado."""
        if not settings.smtp_host or not settings.smtp_sender_email:
            logger.warning("[Alert Email] SMTP não configurado; envio ignorado")
            return False

        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = (
            f"{settings.smtp_sender_name} <{settings.smtp_sender_email}>"
            if settings.smtp_sender_name else settings.smtp_sender_email
        )
        message["To"] = recipient
        message.set_content(body)

        def _send() -> bool:
            smtp_client: smtplib.SMTP | smtplib.SMTP_SSL
            if settings.smtp_use_ssl:
                smtp_client = smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, timeout=10)
            else:
                smtp_client = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10)

            with smtp_client as server:
                if settings.smtp_use_tls and not settings.smtp_use_ssl:
                    server.starttls()
                if settings.smtp_username:
                    server.login(settings.smtp_username, settings.smtp_password)
                server.send_message(message)
            return True

        try:
            logger.info(f"[Alert Email] Para: {recipient}")
            logger.info(f"[Alert Email] Assunto: {subject}")
            return await asyncio.to_thread(_send)
        except Exception as exc:
            logger.error(f"[Alert Email] Erro ao enviar para {recipient}: {exc}")
            return False

    @staticmethod
    async def send_slack(
        webhook_url: str,
        title: str,
        description: str,
        severity: str,
    ) -> bool:
        """Envia alerta para Slack"""
        color_map = {
            "critical": "#FF0000",
            "high": "#FF9900",
            "medium": "#FFFF00",
        }

        payload = {
            "attachments": [
                {
                    "title": title,
                    "text": description,
                    "color": color_map.get(severity, "#CCCCCC"),
                    "footer": "EASM Alert",
                    "ts": int(datetime.now(timezone.utc).timestamp()),
                }
            ]
        }

        return await AlertAction.trigger_webhook(webhook_url, payload)


# ──────────────────────────────────────────────────────────────────────────────
# ALERT MANAGER
# ──────────────────────────────────────────────────────────────────────────────


class AlertManager:
    """Gerencia ciclo de vida de alertas"""

    @staticmethod
    def create_alert(
        db: Session,
        owner_id: int,
        alert_type: AlertType,
        severity: AlertSeverity,
        title: str,
        description: str,
        trigger_value: Optional[float] = None,
        threshold_value: Optional[float] = None,
        asset_id: Optional[int] = None,
        webhook_payload: Optional[Dict[str, Any]] = None,
    ) -> EASMAlert:
        """Cria novo alert no banco de dados"""
        existing = db.query(EASMAlert).filter(
            EASMAlert.owner_id == owner_id,
            EASMAlert.asset_id == asset_id,
            EASMAlert.alert_type == (alert_type.value if isinstance(alert_type, AlertType) else alert_type),
            EASMAlert.title == title,
            EASMAlert.is_resolved == False,
        ).first()
        if existing:
            existing.description = description
            existing.trigger_value = trigger_value
            existing.threshold_value = threshold_value
            existing.webhook_payload = webhook_payload or existing.webhook_payload or {}
            logger.info(f"[Alert] Reutilizado existente: {existing.id} - {title}")
            db.flush()
            return existing

        alert = EASMAlert(
            owner_id=owner_id,
            asset_id=asset_id,
            alert_type=alert_type.value if isinstance(alert_type, AlertType) else alert_type,
            severity=severity.value if isinstance(severity, AlertSeverity) else severity,
            title=title,
            description=description,
            trigger_value=trigger_value,
            threshold_value=threshold_value,
            webhook_payload=webhook_payload or {},
            created_at=datetime.now(timezone.utc),
        )
        db.add(alert)
        db.flush()
        logger.info(f"[Alert] Criado: {alert_type} - {title}")
        return alert

    @staticmethod
    async def process_alert(
        db: Session,
        alert: EASMAlert,
        rule: Optional[EASMAlertRule] = None,
    ) -> None:
        """Processa alerta executando ações configuradas"""
        if not rule:
            # Use default action: log only
            logger.info(f"[Alert] Sem rule configurada, apenas registrado: {alert.title}")
            return

        # Execute webhook if configured
        if rule.webhook_url:
            webhook_success = await AlertAction.trigger_webhook(
                rule.webhook_url,
                {
                    "type": alert.alert_type,
                    "severity": alert.severity,
                    "title": alert.title,
                    "description": alert.description,
                    "trigger_value": alert.trigger_value,
                    "threshold_value": alert.threshold_value,
                },
            )
            if not webhook_success:
                logger.warning(f"[Alert] Webhook falhou: {alert.id}")

        # Execute notifications
        notify_config = rule.notify_channels or ["email"]
        if isinstance(notify_config, dict):
            notify_channels = notify_config.get("channels", ["email"])
        else:
            notify_channels = notify_config
            notify_config = {}

        logger.info(f"[Alert] Notificações: {notify_channels}")

        if "email" in notify_channels:
            email_targets = AlertManager._resolve_email_targets(db, alert, notify_config)
            for recipient in email_targets:
                ok = await AlertAction.send_email(recipient, alert.title, alert.description)
                if not ok:
                    logger.warning(f"[Alert] Email falhou: {alert.id} -> {recipient}")

        if "slack" in notify_channels:
            slack_webhook = AlertManager._resolve_slack_webhook(rule, notify_config)
            if slack_webhook:
                ok = await AlertAction.send_slack(slack_webhook, alert.title, alert.description, alert.severity)
                if not ok:
                    logger.warning(f"[Alert] Slack falhou: {alert.id}")

    @staticmethod
    def check_all_rules(
        db: Session,
        owner_id: int,
    ) -> List[EASMAlert]:
        """
        Verifica todas as rules do usuário e cria alertas se gatilhos disparam
        """
        alerts = []
        rules = db.query(EASMAlertRule).filter(
            EASMAlertRule.owner_id == owner_id,
            EASMAlertRule.enabled == True,
        ).all()

        for rule in rules:
            if rule.rule_type == AlertType.RATING_DROP.value:
                condition = rule.condition or {}
                asset_filter = rule.asset_filter or {}
                threshold = float(condition.get("threshold", 10.0) or 10.0)
                period_hours = int(condition.get("period_hours", 24) or 24)

                assets_query = db.query(Asset).filter(Asset.owner_id == owner_id)
                min_criticality = asset_filter.get("min_criticality")
                if min_criticality is not None:
                    assets_query = assets_query.filter(Asset.criticality_score >= float(min_criticality))

                cutoff = datetime.now(timezone.utc) - timedelta(hours=max(1, period_hours))
                assets = assets_query.all()

                for asset in assets:
                    history = (
                        db.query(AssetRatingHistory)
                        .filter(
                            AssetRatingHistory.asset_id == asset.id,
                            AssetRatingHistory.recorded_at >= cutoff,
                        )
                        .order_by(AssetRatingHistory.recorded_at.desc())
                        .limit(2)
                        .all()
                    )
                    if len(history) < 2:
                        continue

                    current_history, previous_history = history[0], history[1]
                    detected = AlertDetector.detect_rating_drop(
                        db,
                        owner_id,
                        current_history.easm_rating,
                        previous_history.easm_rating,
                        asset_id=asset.id,
                        threshold_points=threshold,
                        period_hours=period_hours,
                    )
                    if detected:
                        alert = AlertManager.create_alert(
                            db,
                            owner_id,
                            AlertType.RATING_DROP,
                            AlertSeverity(detected["severity"]),
                            detected["title"],
                            detected["description"],
                            trigger_value=detected.get("trigger_value"),
                            threshold_value=detected.get("threshold_value"),
                            asset_id=asset.id,
                        )
                        alerts.append(alert)
            elif rule.rule_type == AlertType.CROWN_JEWEL_AGE.value:
                # Iterate assets aplicáveis
                asset_filter = rule.asset_filter or {}
                min_criticality = asset_filter.get("min_criticality", 80)

                assets = db.query(Asset).filter(
                    Asset.owner_id == owner_id,
                    Asset.criticality_score >= min_criticality,
                ).all()

                for asset in assets:
                    detected = AlertDetector.detect_crown_jewel_age(
                        db,
                        owner_id,
                        asset.id,
                    )
                    if detected:
                        alert = AlertManager.create_alert(
                            db,
                            owner_id,
                            AlertType.CROWN_JEWEL_AGE,
                            AlertSeverity(detected["severity"]),
                            detected["title"],
                            detected["description"],
                            asset_id=asset.id,
                        )
                        alerts.append(alert)

        db.commit()
        return alerts

    @staticmethod
    def _resolve_email_targets(db: Session, alert: EASMAlert, notify_config: dict[str, Any]) -> list[str]:
        recipients: list[str] = []

        email_config = notify_config.get("email") if isinstance(notify_config, dict) else None
        if isinstance(email_config, str) and email_config.strip():
            recipients.append(email_config.strip())
        elif isinstance(email_config, list):
            recipients.extend(str(item).strip() for item in email_config if str(item).strip())
        elif isinstance(email_config, dict):
            configured = email_config.get("recipients", [])
            if isinstance(configured, str) and configured.strip():
                recipients.append(configured.strip())
            elif isinstance(configured, list):
                recipients.extend(str(item).strip() for item in configured if str(item).strip())

        if not recipients:
            owner = db.query(User).filter(User.id == alert.owner_id).first()
            if owner and owner.email:
                recipients.append(owner.email)

        unique_recipients: list[str] = []
        for recipient in recipients:
            if recipient not in unique_recipients:
                unique_recipients.append(recipient)
        return unique_recipients

    @staticmethod
    def _resolve_slack_webhook(rule: EASMAlertRule, notify_config: dict[str, Any]) -> str:
        slack_config = notify_config.get("slack") if isinstance(notify_config, dict) else None
        if isinstance(slack_config, str) and slack_config.strip():
            return slack_config.strip()
        if isinstance(slack_config, dict):
            webhook = slack_config.get("webhook_url", "")
            if isinstance(webhook, str) and webhook.strip():
                return webhook.strip()
        return str(rule.webhook_url or "").strip()
