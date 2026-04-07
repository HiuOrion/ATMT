from __future__ import annotations

import asyncio
import contextlib
import json
from dataclasses import dataclass, field
from pathlib import Path
import sys
import time
import uuid
from typing import Any, AsyncIterator, Awaitable, Callable

from demo_web.parsers import parse_source_event_line, parse_wazuh_alert_line
from demo_web.story import timeline_for_mode

DETECTION_RULE_IDS = {100610, 100611, 100612, 100613, 100614, 100501, 100502, 100503}

LineCallback = Callable[[str], Awaitable[None]]
CommandRunner = Callable[[list[str], Path, LineCallback | None], Awaitable[int]]
AlertStreamFactory = Callable[[str], AsyncIterator[str]]


@dataclass
class DemoState:
    state: str = "idle"
    active_mode: str | None = None
    session_id: str = ""
    replayed_events: int = 0
    observed_alerts: int = 0
    first_alert_latency_ms: int | None = None
    last_error: str = ""
    services: dict[str, bool] = field(
        default_factory=lambda: {"docker_up": False, "manager_configured": False}
    )
    command_log: list[str] = field(default_factory=list)
    completed_steps: list[str] = field(default_factory=list)
    last_source_event: dict[str, Any] | None = None
    last_alert: dict[str, Any] | None = None


async def run_command_stream(command: list[str], cwd: Path, on_line: LineCallback | None = None) -> int:
    process = await asyncio.create_subprocess_exec(
        *command,
        cwd=str(cwd),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    try:
        assert process.stdout is not None
        while True:
            line = await process.stdout.readline()
            if not line:
                break
            if on_line is not None:
                await on_line(line.decode("utf-8", errors="replace").rstrip())
        return await process.wait()
    except asyncio.CancelledError:
        process.kill()
        with contextlib.suppress(ProcessLookupError):
            await process.wait()
        raise


async def docker_alert_stream(container_name: str) -> AsyncIterator[str]:
    command = [
        "docker",
        "exec",
        container_name,
        "sh",
        "-lc",
        "touch /var/ossec/logs/alerts/alerts.json && tail -n 0 -F /var/ossec/logs/alerts/alerts.json",
    ]
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    try:
        assert process.stdout is not None
        while True:
            line = await process.stdout.readline()
            if not line:
                break
            yield line.decode("utf-8", errors="replace").rstrip()
    finally:
        if process.returncode is None:
            process.kill()
            with contextlib.suppress(ProcessLookupError):
                await process.wait()


class SessionManager:
    def __init__(
        self,
        root: Path,
        *,
        command_runner: CommandRunner = run_command_stream,
        alert_stream_factory: AlertStreamFactory = docker_alert_stream,
        container_name: str = "atmt-wazuh-manager-live",
    ) -> None:
        self.root = root
        self.command_runner = command_runner
        self.alert_stream_factory = alert_stream_factory
        self.container_name = container_name
        self.state = DemoState()
        self._state_lock = asyncio.Lock()
        self._subscribers: set[asyncio.Queue[str]] = set()
        self._action_task: asyncio.Task[None] | None = None
        self._alert_task: asyncio.Task[None] | None = None
        self._first_event_monotonic: float | None = None
        self._runtime_paths = [
            self.root / "runtime" / "replay" / "live_demo.jsonl",
            self.root / "runtime" / "replay" / "demo_simulation.log",
        ]

    def snapshot(self) -> dict[str, Any]:
        return {
            "state": self.state.state,
            "active_mode": self.state.active_mode,
            "session_id": self.state.session_id,
            "replayed_events": self.state.replayed_events,
            "observed_alerts": self.state.observed_alerts,
            "first_alert_latency_ms": self.state.first_alert_latency_ms,
            "last_error": self.state.last_error,
            "services": dict(self.state.services),
            "command_log": list(self.state.command_log[-12:]),
            "completed_steps": list(self.state.completed_steps),
            "last_source_event": self.state.last_source_event,
            "last_alert": self.state.last_alert,
            "timeline": timeline_for_mode(self.state.active_mode),
        }

    async def subscribe(self) -> asyncio.Queue[str]:
        queue: asyncio.Queue[str] = asyncio.Queue()
        self._subscribers.add(queue)
        await queue.put(self._format_sse("status", self.snapshot()))
        return queue

    def unsubscribe(self, queue: asyncio.Queue[str]) -> None:
        self._subscribers.discard(queue)

    async def setup(self) -> None:
        async with self._state_lock:
            if self.state.state in {"setting_up", "running"}:
                raise RuntimeError("Một tác vụ dài đang chạy.")
            self._set_state("setting_up", active_mode=None, clear_error=True)
            self._action_task = asyncio.create_task(self._run_setup())

    async def start_demo(self, *, mode: str, limit: int | None = None, delay: float | None = None) -> None:
        async with self._state_lock:
            if self.state.state in {"setting_up", "running"}:
                raise RuntimeError("Demo đang bận.")
            if not self.state.services["manager_configured"]:
                raise RuntimeError("Hãy thiết lập live stack trước.")
            self._prepare_new_session(mode)
            self.state.state = "running"
            await self._broadcast("status", self.snapshot())
            self._action_task = asyncio.create_task(self._run_demo(mode=mode, limit=limit, delay=delay))

    async def reset(self) -> None:
        await self._cancel_background_tasks()
        for path in self._runtime_paths:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("", encoding="utf-8")
        self._first_event_monotonic = None
        next_state = "ready" if self.state.services["manager_configured"] else "idle"
        self.state = DemoState(
            state=next_state,
            services=dict(self.state.services),
        )
        await self._broadcast("status", self.snapshot())

    async def wait_for_idle(self, timeout: float = 5.0) -> None:
        deadline = time.monotonic() + timeout
        while self.state.state in {"setting_up", "running"}:
            if time.monotonic() >= deadline:
                raise TimeoutError("Session manager did not become idle in time.")
            await asyncio.sleep(0.05)

    def _set_state(self, state: str, *, active_mode: str | None = None, clear_error: bool = False) -> None:
        self.state.state = state
        self.state.active_mode = active_mode
        if clear_error:
            self.state.last_error = ""

    async def _cancel_background_tasks(self) -> None:
        tasks = [task for task in [self._action_task, self._alert_task] if task is not None]
        for task in tasks:
            task.cancel()
        for task in tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        self._action_task = None
        self._alert_task = None

    async def _run_setup(self) -> None:
        try:
            await self._run_command(
                ["docker", "compose", "-f", "infra/docker-compose.live.yml", "up", "-d"],
                "docker compose",
            )
            self.state.services["docker_up"] = True
            await self._run_command(
                ["powershell", "-ExecutionPolicy", "Bypass", "-File", ".\\infra\\configure_live_manager.ps1"],
                "configure manager",
            )
            self.state.services["manager_configured"] = True
            for path in self._runtime_paths:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("", encoding="utf-8")
            self._set_state("ready")
            await self._broadcast("status", self.snapshot())
        except Exception as exc:
            await self._fail(exc)
        finally:
            self._action_task = None

    async def _run_demo(self, *, mode: str, limit: int | None, delay: float | None) -> None:
        self._alert_task = asyncio.create_task(self._watch_alerts(self.state.session_id))
        try:
            if mode == "lockbit_public":
                command = [
                    sys.executable,
                    "simulation/replay_public_lockbit.py",
                    "--truncate",
                    "--emit-stdout",
                    "--demo-session",
                    self.state.session_id,
                    "--limit",
                    str(limit or 8),
                    "--delay",
                    str(delay if delay is not None else 0.5),
                    "--start-delay",
                    "0.8",
                ]
            elif mode == "safe_file_activity":
                command = [
                    sys.executable,
                    "simulation/safe_ransomware_sim.py",
                    "--output-dir",
                    "runtime/replay/demo_files",
                    "--log-file",
                    "runtime/replay/demo_simulation.log",
                    "--clean",
                    "--emit-stdout",
                    "--demo-session",
                    self.state.session_id,
                    "--count",
                    str(limit or 18),
                ]
            else:
                raise RuntimeError(f"Unsupported mode: {mode}")

            await self._run_command(command, f"start demo {mode}", parse_source_events=True)
            await asyncio.sleep(2.0)
            if self.state.state != "error":
                self.state.state = "completed"
                await self._broadcast("status", self.snapshot())
        except Exception as exc:
            await self._fail(exc)
        finally:
            if self._alert_task is not None:
                self._alert_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await self._alert_task
                self._alert_task = None
            self._action_task = None

    async def _run_command(self, command: list[str], label: str, *, parse_source_events: bool = False) -> None:
        async def on_line(line: str) -> None:
            if parse_source_events:
                event = parse_source_event_line(line)
                if event is not None:
                    await self._handle_source_event(event)
                    return
            await self._append_command_log(f"[{label}] {line}")

        return_code = await self.command_runner(command, self.root, on_line)
        if return_code != 0:
            raise RuntimeError(f"Lệnh thất bại ({label}): exit code {return_code}")

    async def _watch_alerts(self, session_id: str) -> None:
        try:
            async for line in self.alert_stream_factory(self.container_name):
                alert = parse_wazuh_alert_line(line, session_id)
                if alert is None:
                    continue
                self.state.observed_alerts += 1
                self.state.last_alert = alert
                if alert["rule_id"] in DETECTION_RULE_IDS:
                    if self._first_event_monotonic is not None and self.state.first_alert_latency_ms is None:
                        self.state.first_alert_latency_ms = int((time.monotonic() - self._first_event_monotonic) * 1000)
                    await self._complete_step("detection_triggered")
                await self._broadcast("alert", alert)
                await self._broadcast("metric", self._metric_payload())
                await self._broadcast("status", self.snapshot())
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            await self._append_command_log(f"[alerts] {exc}")

    async def _handle_source_event(self, event: dict[str, Any]) -> None:
        self.state.replayed_events += 1
        self.state.last_source_event = event
        if self._first_event_monotonic is None:
            self._first_event_monotonic = time.monotonic()
        await self._complete_step(str(event.get("story_phase", "activity")))
        await self._broadcast("source_event", event)
        await self._broadcast(
            "story_step",
            {"step_id": event.get("story_phase", "activity"), "title": event.get("story_title", "Observed activity")},
        )
        await self._broadcast("metric", self._metric_payload())
        await self._broadcast("status", self.snapshot())

    async def _complete_step(self, step_id: str) -> None:
        if step_id and step_id not in self.state.completed_steps:
            self.state.completed_steps.append(step_id)

    def _prepare_new_session(self, mode: str) -> None:
        self._first_event_monotonic = None
        self.state.active_mode = mode
        self.state.state = "ready"
        self.state.session_id = uuid.uuid4().hex[:12]
        self.state.replayed_events = 0
        self.state.observed_alerts = 0
        self.state.first_alert_latency_ms = None
        self.state.last_error = ""
        self.state.command_log = []
        self.state.completed_steps = []
        self.state.last_source_event = None
        self.state.last_alert = None

    async def _fail(self, exc: Exception) -> None:
        self.state.state = "error"
        self.state.last_error = str(exc)
        await self._broadcast("error", {"message": str(exc)})
        await self._broadcast("status", self.snapshot())

    async def _append_command_log(self, line: str) -> None:
        self.state.command_log.append(line)
        self.state.command_log = self.state.command_log[-50:]
        await self._broadcast("command_log", {"line": line})

    async def _broadcast(self, event_type: str, payload: dict[str, Any]) -> None:
        message = self._format_sse(event_type, payload)
        stale_queues: list[asyncio.Queue[str]] = []
        for queue in self._subscribers:
            try:
                queue.put_nowait(message)
            except asyncio.QueueFull:
                stale_queues.append(queue)
        for queue in stale_queues:
            self._subscribers.discard(queue)

    def _metric_payload(self) -> dict[str, Any]:
        return {
            "replayed_events": self.state.replayed_events,
            "observed_alerts": self.state.observed_alerts,
            "first_alert_latency_ms": self.state.first_alert_latency_ms,
            "active_mode": self.state.active_mode,
        }

    @staticmethod
    def _format_sse(event_type: str, payload: dict[str, Any]) -> str:
        return f"event: {event_type}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"
