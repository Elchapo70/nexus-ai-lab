from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_explain_eval():
    result = client.post("/api/explain", json={"rule": "EVAL"})
    assert result.status_code == 200
    assert result.json()["method"] == "rule-based"
    assert "eval" in result.json()["explanation"]

def test_explain_unknown():
    assert client.post("/api/explain", json={"rule": "UNKNOWN"}).status_code == 404

def test_explain_validation():
    assert client.post("/api/explain", json={"rule": ""}).status_code == 422
