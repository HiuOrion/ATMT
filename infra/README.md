# Infrastructure Notes

This folder contains the infrastructure assets for a local Wazuh demo that runs on Docker Desktop. The primary classroom path is the manager-only live compose file, which replays public Lockbit-derived events into Wazuh without running malware.

## Recommended Live Demo Compose

Use `docker-compose.live.yml` for the classroom demo:

```powershell
docker compose -f infra/docker-compose.live.yml up -d
powershell -ExecutionPolicy Bypass -File .\infra\configure_live_manager.ps1
```

Replay events:

```powershell
python simulation/replay_public_lockbit.py --limit 8 --delay 0.5 --start-delay 1.0
```

Watch alerts:

```powershell
docker exec atmt-wazuh-manager-live tail -f /var/ossec/logs/alerts/alerts.json
```

## Public Replay Rules

The manager-only compose mounts:

- `../runtime/replay/`

The post-start script `configure_live_manager.ps1` then:

- copies `wazuh/custom_rules/public_lockbit_rules.xml` into the container
- appends the `localfile` monitor for `live_demo.jsonl`
- creates required log directories
- restarts the manager cleanly

The replay source consumed by the live script is:

- `data/public_replay/lockbit_public.jsonl`

The live destination file watched by Wazuh is:

- `runtime/replay/live_demo.jsonl`

The safe simulation destination file watched by Wazuh is:

- `runtime/replay/demo_simulation.log`

## Web Control Plane

The repo now ships with a local web app that wraps the live classroom flow:

```powershell
python -m demo_web
```

Open <http://127.0.0.1:8000>, click `Thiết lập`, then choose either:

- `Chạy Lockbit` for the public telemetry replay
- `Chạy Mô phỏng an toàn` for the harmless file-activity simulation

The web UI keeps the manager-only stack and replay files unchanged; it only orchestrates the existing scripts and streams state to the browser.

## Optional Full Stack

The repository still includes `docker-compose.yml` for broader experimentation, but the live classroom demo should use the manager-only path unless you explicitly want to troubleshoot the full stack.

## Notes

- Use public telemetry for the ransomware evidence portion of the demo.
- Do not use this environment to acquire or run real malware.
