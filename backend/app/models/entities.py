from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, ForeignKey, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


def now_utc():
    return datetime.now(timezone.utc)


class RiskProfile(Base):
    __tablename__ = "risk_profiles"

    id: Mapped[int] = mapped_column(primary_key=True)
    profile_name: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    ip_reputation: Mapped[int] = mapped_column(Integer, default=60)
    network_anonymity: Mapped[int] = mapped_column(Integer, default=60)
    malicious_infrastructure: Mapped[int] = mapped_column(Integer, default=60)
    geographic_risk: Mapped[int] = mapped_column(Integer, default=60)
    transaction_behavior: Mapped[int] = mapped_column(Integer, default=60)
    account_characteristics: Mapped[int] = mapped_column(Integer, default=60)
    sensitivity: Mapped[str] = mapped_column(String(20), default="balanced")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    analyses: Mapped[list["RiskAnalysis"]] = relationship(back_populates="risk_profile")


class Transaction(Base):
    __tablename__ = "transactions"

    id: Mapped[int] = mapped_column(primary_key=True)
    transaction_id: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    ip_address: Mapped[str] = mapped_column(String(45))
    transaction_amount: Mapped[float] = mapped_column(Float)
    currency: Mapped[str] = mapped_column(String(3), default="USD")
    user_country: Mapped[str | None] = mapped_column(String(2), nullable=True)
    transaction_country: Mapped[str | None] = mapped_column(String(2), nullable=True)
    transaction_velocity: Mapped[int | None] = mapped_column(Integer, nullable=True)
    account_age_days: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    analyses: Mapped[list["RiskAnalysis"]] = relationship(back_populates="transaction")


class RiskAnalysis(Base):
    __tablename__ = "risk_analyses"

    id: Mapped[int] = mapped_column(primary_key=True)
    transaction_id: Mapped[int] = mapped_column(ForeignKey("transactions.id"))
    risk_profile_id: Mapped[int] = mapped_column(ForeignKey("risk_profiles.id"))
    risk_score: Mapped[float] = mapped_column(Float)
    risk_level: Mapped[str] = mapped_column(String(20))
    explanation: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    transaction: Mapped[Transaction] = relationship(back_populates="analyses")
    risk_profile: Mapped[RiskProfile] = relationship(back_populates="analyses")
    provider_results: Mapped[list["ProviderResult"]] = relationship(back_populates="analysis", cascade="all, delete-orphan")


class ProviderResult(Base):
    __tablename__ = "provider_results"

    id: Mapped[int] = mapped_column(primary_key=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("risk_analyses.id"))
    provider_name: Mapped[str] = mapped_column(String(80))
    signals: Mapped[list] = mapped_column(JSON, default=list)
    analysis: Mapped[RiskAnalysis] = relationship(back_populates="provider_results")
