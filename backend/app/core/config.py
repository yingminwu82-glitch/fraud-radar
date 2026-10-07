from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import model_validator


class Settings(BaseSettings):
    app_name: str = "Fraud Radar API"
    database_url: str = "sqlite:///./fraud_radar.db"
    use_mock_apis: bool = True
    frontend_origin: str = "http://localhost:5173"
    llm_provider: str = "mock"
    risk_low_threshold: int = 29
    risk_medium_threshold: int = 59
    risk_high_threshold: int = 79

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    @model_validator(mode="after")
    def thresholds_are_ordered(self):
        values = (self.risk_low_threshold, self.risk_medium_threshold, self.risk_high_threshold)
        if not (0 <= values[0] < values[1] < values[2] <= 99):
            raise ValueError("Risk thresholds must be ordered from 0 to 99")
        return self


settings = Settings()

RISK_THRESHOLDS = {"low": settings.risk_low_threshold, "medium": settings.risk_medium_threshold, "high": settings.risk_high_threshold}
