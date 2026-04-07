import asyncio
import json
from pathlib import Path

from demo_web.session import SessionManager


def test_session_manager_runs_setup_and_demo() -> None:
    async def scenario() -> None:
        root = Path(__file__).resolve().parents[1]
        commands: list[list[str]] = []
        manager: SessionManager | None = None

        async def fake_runner(command: list[str], cwd: Path, on_line):
            commands.append(command)
            if command[:2] == ["docker", "compose"] and on_line is not None:
                await on_line("manager starting")
            joined = " ".join(command)
            if "replay_public_lockbit.py" in joined and on_line is not None and manager is not None:
                event = {
                    "dataset": "public_lockbit",
                    "signal_type": "shadow_delete",
                    "description": "Shadow delete observed",
                    "demo_session": manager.state.session_id,
                    "sequence": 1,
                }
                await on_line(f"SOURCE_EVENT {json.dumps(event)}")
            return 0

        async def fake_alert_stream(container_name: str):
            if manager is None:
                return
            yield json.dumps(
                {
                    "timestamp": "2026-04-07T10:00:01Z",
                    "rule": {"id": 100610, "level": 14, "description": "Lockbit replay"},
                    "data": {"demo_session": manager.state.session_id},
                    "full_log": f'{{"demo_session":"{manager.state.session_id}"}}',
                }
            )

        manager = SessionManager(root, command_runner=fake_runner, alert_stream_factory=fake_alert_stream)
        await manager.setup()
        await manager.wait_for_idle()
        assert manager.snapshot()["state"] == "ready"

        await manager.start_demo(mode="lockbit_public", limit=1, delay=0.0)
        await manager.wait_for_idle(timeout=8.0)
        snapshot = manager.snapshot()

        assert snapshot["state"] == "completed"
        assert snapshot["replayed_events"] == 1
        assert snapshot["observed_alerts"] == 1
        assert "shadow_tampering" in snapshot["completed_steps"]
        assert "detection_triggered" in snapshot["completed_steps"]
        assert any("docker-compose.live.yml" in " ".join(command) for command in commands)

    asyncio.run(scenario())


def test_session_manager_blocks_parallel_setup() -> None:
    async def scenario() -> None:
        root = Path(__file__).resolve().parents[1]

        async def slow_runner(command: list[str], cwd: Path, on_line):
            await asyncio.sleep(0.2)
            return 0

        async def fake_alert_stream(container_name: str):
            if False:
                yield ""

        manager = SessionManager(root, command_runner=slow_runner, alert_stream_factory=fake_alert_stream)
        await manager.setup()
        try:
            await manager.setup()
        except RuntimeError as exc:
            assert "đang chạy" in str(exc)
        else:
            raise AssertionError("Expected RuntimeError")
        await manager.wait_for_idle()

    asyncio.run(scenario())
