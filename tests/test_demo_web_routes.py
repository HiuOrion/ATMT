from pathlib import Path

from fastapi.testclient import TestClient

from demo_web.app import create_app
from demo_web.session import SessionManager


def build_fake_manager(root: Path) -> SessionManager:
    async def fake_runner(command, cwd, on_line):
        return 0

    async def fake_alert_stream(container_name: str):
        if False:
            yield ""

    manager = SessionManager(root, command_runner=fake_runner, alert_stream_factory=fake_alert_stream)
    manager.state.services["docker_up"] = True
    manager.state.services["manager_configured"] = True
    manager.state.state = "ready"
    return manager


def test_routes_return_expected_shapes() -> None:
    root = Path(__file__).resolve().parents[1]
    app = create_app(root=root, session_manager=build_fake_manager(root))

    with TestClient(app) as client:
        response = client.get("/")
        assert response.status_code == 200
        assert "ATMT Wazuh Live Demo" in response.text

        status_response = client.get("/api/status")
        assert status_response.status_code == 200
        payload = status_response.json()
        assert payload["state"] == "ready"
        assert "timeline" in payload

        reset_response = client.post("/api/reset")
        assert reset_response.status_code == 200

        start_response = client.post("/api/demo/start", json={"mode": "lockbit_public", "limit": 4, "delay": 0.2})
        assert start_response.status_code == 200
        assert start_response.json()["accepted"] is True
