import os

os.environ["DATABASE_URL"] = "sqlite:///./test_fraud_radar.db"
os.environ["USE_MOCK_APIS"] = "true"

import pytest
from fastapi.testclient import TestClient

from app.core.database import Base, engine
from app.main import app


@pytest.fixture
def client():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with TestClient(app) as test_client:
        yield test_client
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def profile_payload():
    return {"profile_name": "Test Balanced", "ip_reputation": 60, "network_anonymity": 60, "malicious_infrastructure": 60, "geographic_risk": 60, "transaction_behavior": 60, "account_characteristics": 60, "sensitivity": "balanced"}
