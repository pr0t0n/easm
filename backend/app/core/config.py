from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "ScriptKidd.o"
    app_env: str = "development"
    secret_key: str = "change_me"
    # Token de acesso: 24h por padrao.
    # Scans longos nao sao afetados — a execucao ocorre inteiramente nos workers
    # Celery, sem validacao JWT. O token so e necessario nas chamadas HTTP do frontend.
    access_token_expire_minutes: int = 1440
    # Token de refresh: 7 dias. Usado pelo frontend para reemitir access tokens
    # silenciosamente sem forcar re-login durante sessoes longas de monitoramento.
    refresh_token_expire_days: int = 7
    admin_email: str = "admin@example.com"
    admin_password: str = "admin123"

    database_url: str
    redis_url: str
    celery_broker_url: str
    celery_result_backend: str
    langgraph_checkpointer_dsn: str | None = None

    ollama_base_url: str = "http://ollama:11434"
    llm_primary_provider: str = "ollama"
    llm_primary_model: str = "llama3.2:3b"
    ollama_model: str = "llama3.2:3b"
    ollama_qwen_model: str = "llama3.2:3b"
    ollama_cloudcode_model: str = "llama3.2:3b"
    llm_evaluation_model: str = "llama3.2:3b"
    agent_orchestrator_enabled: bool = True
    llm_reasoning_enabled: bool = True
    llm_operator_enabled: bool = True
    enforce_scan_authorization_for_public_targets: bool = True
    llm_risk_enabled: bool = False
    llm_risk_provider: str = "ollama"
    llm_risk_ollama_model: str = "llama3.2:3b"
    llm_risk_strategy_profile: str = "balanced"
    llm_risk_strategies: str = "prompt-injection,jailbreak,jailbreak:composite"
    llm_risk_num_tests: int = 5
    llm_risk_timeout_seconds: int = 60
    ai_recommendations_use_ollama: bool = True
    ai_recommendations_timeout_seconds: int = 60
    frontend_origin: str = "http://localhost:5173"
    frontend_origins: str = "http://localhost:5173,http://127.0.0.1:5173,http://localhost:5174,http://127.0.0.1:5174"
    frontend_origin_regex: str | None = None

    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_sender_email: str = ""
    smtp_sender_name: str = "ScriptKidd.o"
    smtp_use_tls: bool = True
    smtp_use_ssl: bool = False

    # ── Kali runner (centralized tool executor) ────────────────────────────
    # SINGLE source of truth for offensive tools. All workers dispatch HTTP
    # jobs to this sidecar; backend/worker images carry NO tools themselves.
    use_kali_executor: bool = True
    kali_runner_url: str = "http://kali_runner:8088"
    kali_executor_tools: str = ""  # legacy canary list; ignored when use_kali_executor=true
    mcp_server_url: str = "http://mcp_server:3000"
    mcp_rag_enabled: bool = True
    mcp_execute_tools_via_mcp: bool = True
    mcp_default_top_k: int = 5
    mcp_request_timeout_seconds: int = 1800
    offensive_operator_enabled: bool = True
    offensive_operator_phase_queue_enabled: bool = True
    offensive_operator_phase_task_budget: int = 4
    scan_parallelize_default: bool = True
    scan_parallel_target_batch_size: int = 1024
    scan_parallel_wait_seconds: int = 60
    scan_work_queue_enabled: bool = True
    scan_work_queue_dispatch_limit: int = 300
    scan_work_queue_lease_seconds: int = 1800
    # Capacidade por classe de recurso — alinhadas com KALI_MAX_PARALLEL=100.
    # cap_light=60: httpx/whatweb/subfinder — leves, I/O-bound, escalam bem.
    # cap_medium=40: nuclei/ffuf/dalfox — CPU+net moderado.
    # cap_heavy=24: nmap/wapiti/sqlmap — CPU pesado; 24 = ~4 ondas para 50 targets.
    # cap_oob=8:   interactsh — callbacks externos, limitado por upstream.
    # Reduzidos p/ varredura EDUCADA: caps antigos (60/40/24) somavam ~132 tools
    # concorrentes → saturavam o link do operador (internet caía) e geravam os
    # próprios timeouts. Alinhados ao KALI_MAX_PARALLEL=10 (chokepoint real).
    scan_work_queue_cap_light: int = 16
    scan_work_queue_cap_medium: int = 8
    scan_work_queue_cap_heavy: int = 4
    scan_work_queue_cap_oob: int = 3

    # Vulnerability testing catalog exposed by docker-compose. The list uses
    # the markdown filename slugs from skills/vulnerability_testing/*.md.
    vulnerability_catalog_enabled: bool = True
    vulnerability_catalog_dir: str = "/app/skills/vulnerability_testing"
    vulnerability_catalog_skills: str = ""

    # Blocks "full" scans when the latest tool_health_snapshot shows required
    # tools missing_profile/missing_binary. Fail-open when no snapshot exists yet
    # (see refresh_tool_health_snapshot beat task, which keeps the snapshot fresh).
    enforce_tool_health_precheck: bool = True

    # Pentest automation infrastructure. Services are declared in docker-compose
    # and may be disabled by env in lightweight/dev runs.
    evidence_storage_path: str = "/evidence"
    browser_runner_url: str = "http://browser_runner:9222"
    enable_browser_capture: bool = True
    browser_capture_har: bool = True
    browser_capture_screenshots: bool = True
    browser_max_duration_seconds: int = 180
    enable_artifact_replay: bool = True
    enable_oob_validation: bool = False


settings = Settings()
