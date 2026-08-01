from fastapi.testclient import TestClient

from agent_template.main import create_app


def test_hello_world() -> None:
    client = TestClient(create_app())

    response = client.get("/")

    assert response.status_code == 200
    assert response.json() == {"message": "hello world"}


def test_healthz() -> None:
    client = TestClient(create_app())

    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}
