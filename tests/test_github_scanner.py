import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from app.main import app
from app.github_scanner import scan_github

@pytest.mark.parametrize("value", ["http://example.com/a/b", "localhost:8000/x", "../private", "https://github.com/a/b/issues"])
def test_rejects_invalid_repository(value):
    with pytest.raises(HTTPException) as exc:
        scan_github(value)
    assert exc.value.status_code == 422

def test_github_endpoint_rejects_bad_input():
    response = TestClient(app).post("/api/scan/github", json={"repository": "localhost/private"})
    assert response.status_code == 422
