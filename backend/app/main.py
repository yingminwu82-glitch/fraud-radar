from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes.api import router
from app.core.config import settings
from app.core.database import Base, SessionLocal, engine
from app.models.entities import RiskProfile


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    # Lightweight additive migration for existing SQLite prototype databases.
    if engine.dialect.name == "sqlite":
        from sqlalchemy import inspect, text
        columns={col["name"] for col in inspect(engine).get_columns("provider_results")}
        migrations={"raw_result":"JSON","status":"VARCHAR(32) NOT NULL DEFAULT 'success'","latency_ms":"FLOAT","error_message":"VARCHAR(500)","subject":"VARCHAR(255)","source_mode":"VARCHAR(16) NOT NULL DEFAULT 'mock'","created_at":"DATETIME"}
        with engine.begin() as conn:
            for name,sql_type in migrations.items():
                if name not in columns: conn.execute(text(f"ALTER TABLE provider_results ADD COLUMN {name} {sql_type}"))
        analysis_columns={col["name"] for col in inspect(engine).get_columns("risk_analyses")}
        if "structured_result" not in analysis_columns:
            with engine.begin() as conn: conn.execute(text("ALTER TABLE risk_analyses ADD COLUMN structured_result JSON"))
        chat_session_columns={col["name"] for col in inspect(engine).get_columns("chat_sessions")}
        if "context_type" not in chat_session_columns:
            with engine.begin() as conn: conn.execute(text("ALTER TABLE chat_sessions ADD COLUMN context_type VARCHAR(32) NOT NULL DEFAULT 'report'"))
    with SessionLocal() as db:
        if db.query(RiskProfile).count() == 0:
            db.add_all([
                RiskProfile(profile_name="Balanced", ip_reputation=60, network_anonymity=60, malicious_infrastructure=60, geographic_risk=60, transaction_behavior=60, account_characteristics=60, sensitivity="balanced"),
                RiskProfile(profile_name="Security Focused", ip_reputation=80, network_anonymity=90, malicious_infrastructure=95, geographic_risk=50, transaction_behavior=40, account_characteristics=30, sensitivity="conservative"),
                RiskProfile(profile_name="Transaction Focused", ip_reputation=35, network_anonymity=35, malicious_infrastructure=45, geographic_risk=60, transaction_behavior=95, account_characteristics=45, sensitivity="aggressive"),
            ])
            db.commit()
    yield


app = FastAPI(title=settings.app_name, version="0.1.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=[settings.frontend_origin], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.include_router(router)

# In the Vercel deployment, serve the built Vite app from the same origin as
# the API. This keeps the existing relative /api URLs working without a proxy.
frontend_dist = Path(__file__).resolve().parents[2] / "frontend" / "dist"
if frontend_dist.is_dir():
    from fastapi.staticfiles import StaticFiles

    app.mount("/", StaticFiles(directory=frontend_dist, html=True), name="frontend")
