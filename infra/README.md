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

## Optional Full Stack

The repository still includes `docker-compose.yml` for broader experimentation, but the live classroom demo should use the manager-only path unless you explicitly want to troubleshoot the full stack.

## Notes

- Use public telemetry for the ransomware evidence portion of the demo.
- Do not use this environment to acquire or run real malware.
