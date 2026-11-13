from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import model_validator
import os
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parents[2]


def default_database_url() -> str:
    # Vercel's Python runtime cannot rely on a writable SQLite file. Use an
    # in-memory SQLite database for the demo; production persistence requires
    # configuring a hosted DATABASE_URL.
    if os.getenv("VERCEL") or os.getenv("VERCEL_ENV") or Path("/var/task").is_dir():
        return "sqlite://"
    return "sqlite:///./fraud_radar.db"


class Settings(BaseSettings):
    app_name: str = "Fraud Radar API"
    database_url: str = default_database_url()
    use_mock_apis: bool = True
    frontend_origin: str = "http://localhost:5173"
    llm_provider: str = "mock"
    risk_low_threshold: int = 29
    risk_medium_threshold: int = 59
    risk_high_threshold: int = 79
    ffraud_api_key: str | None = None
    ipdb_api_key: str | None = None
    virustotal_api_key: str | None = None
    provider_timeout_seconds: float = 8.0
    provider_cache_ttl_seconds: int = 86400
    use_mock_llm: bool = True
    deepseek_api_key: str | None = None
    deepseek_model: str = "deepseek-v4-flash"
    deepseek_base_url: str = "https://api.deepseek.com"
    deepseek_timeout_seconds: float = 30.0

    model_config = SettingsConfigDict(env_file=BACKEND_DIR / ".env", env_file_encoding="utf-8", extra="ignore")

    @model_validator(mode="after")
    def thresholds_are_ordered(self):
        values = (self.risk_low_threshold, self.risk_medium_threshold, self.risk_high_threshold)
        if not (0 <= values[0] < values[1] < values[2] <= 99):
            raise ValueError("Risk thresholds must be ordered from 0 to 99")
        return self


settings = Settings()

RISK_THRESHOLDS = {"low": settings.risk_low_threshold, "medium": settings.risk_medium_threshold, "high": settings.risk_high_threshold}
