from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress


class RiskProfileBase(BaseModel):
    profile_name: str = Field(min_length=1, max_length=80)
    ip_reputation: int = Field(ge=0, le=100)
    network_anonymity: int = Field(ge=0, le=100)
    malicious_infrastructure: int = Field(ge=0, le=100)
    geographic_risk: int = Field(ge=0, le=100)
    transaction_behavior: int = Field(ge=0, le=100)
    account_characteristics: int = Field(ge=0, le=100)
    sensitivity: Literal["conservative", "balanced", "aggressive"] = "balanced"


class RiskProfileCreate(RiskProfileBase):
    pass


class RiskProfileUpdate(RiskProfileBase):
    pass


class RiskProfileRead(RiskProfileBase):
    id: int
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class TransactionInput(BaseModel):
    transaction_id: str = Field(min_length=1, max_length=80)
    ip_address: IPvAnyAddress
    transaction_amount: float = Field(ge=0, le=100_000_000)
    currency: str = Field(default="USD", min_length=3, max_length=3)
    user_country: str | None = Field(default=None, min_length=2, max_length=2)
    transaction_country: str | None = Field(default=None, min_length=2, max_length=2)
    transaction_velocity: int | None = Field(default=None, ge=0, le=100_000)
    account_age_days: int | None = Field(default=None, ge=0, le=100_000)


class AnalyzeRequest(TransactionInput):
    risk_profile_id: int


class NormalizedSignal(BaseModel):
    category: str
    factor: str
    value: str | float | bool | None = None
    risk_score: float = Field(ge=0, le=100)
    confidence: float = Field(default=1.0, ge=0, le=1)
    provider: str
    missing: bool = False


class FactorScore(BaseModel):
    factor: str
    raw_signal: str
    risk_score: float
    user_preference: int
    weight: float
    contribution: float
    providers: list[str]


class AnalyzeResponse(BaseModel):
    transaction_id: str
    risk_score: float
    risk_level: str
    risk_profile: str
    factor_scores: list[FactorScore]
    provider_results: list[dict]
    provider_agreement: list[str]
    missing_signals: list[str]
    explanation: list[str]
