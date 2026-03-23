from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "VALID ASM - vASM"
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
    ollama_model: str = "llama3"
    ollama_qwen_model: str = "qwen2.5:7b"
    ollama_cloudcode_model: str = "llama3.1:8b"
    ai_recommendations_use_ollama: bool = False
    ai_recommendations_timeout_seconds: int = 20
    frontend_origin: str = "http://localhost:5173"
    frontend_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    frontend_origin_regex: str | None = None

    nessus_enabled: bool = False
    nessus_url: str = ""
    nessus_access_key: str = ""
    nessus_secret_key: str = ""
    nessus_verify_tls: bool = True


settings = Settings()
