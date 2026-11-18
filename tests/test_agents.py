from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_agents_review():
    result = client.post("/api/agents/review", json={"project":"demo", "files_scanned":1, "findings":[{"rule":"EVAL","severity":"medium","file":"a.py","line":2}]})
    assert result.status_code == 200
    data = result.json()
    assert len(data["agents"]) == 3
    assert data["agents"][1]["tasks"][0]["rule"] == "EVAL"
    assert data["llm_enabled"] is False

def test_ai_disabled_by_default(monkeypatch):
    monkeypatch.delenv("NEXUS_AI_ENABLED", raising=False)
    response = client.post("/api/agents/ai-review", json={"project":"demo","findings":[]})
    assert response.status_code == 503

def test_agent_rejects_oversized_request():
    response = client.post("/api/agents/review", json={"project":"demo","files_scanned":1,"findings":[{}]*101})
    assert response.status_code == 422
