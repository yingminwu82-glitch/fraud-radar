from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes.api import router
from app.core.config import settings
from app.core.database import Base, SessionLocal, engine
from app.models.entities import RiskProfile


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
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
