# Infrastructure Notes

This folder contains the infrastructure assets for a local Wazuh demo that runs on Docker Desktop. The goal is to demonstrate detection workflow and reporting, not to detonate malware.

## Dockerized Wazuh

1. Make sure Docker Desktop and WSL2 are installed.
2. Start the stack:

```powershell
cd infra
docker compose up -d
```

3. Confirm the containers are healthy:

```powershell
docker compose ps
```

4. Open the dashboard at `https://localhost` and sign in with the credentials defined in the compose file defaults.

## Custom Parsing for the Live Demo

The safe simulator writes plain-text events to `simulation/output/demo_events.log`. To ingest them as live alerts:

1. Install the Wazuh agent on the host machine.
2. Add the example localfile block from `wazuh/agent_localfile_example.xml` to the host agent configuration.
3. Mount the custom decoder and rule files from this repo into the manager container:
   - `wazuh/custom_decoders/ransomware_demo_decoders.xml`
   - `wazuh/custom_rules/ransomware_demo_rules.xml`
4. Restart the Wazuh manager and the host Wazuh agent.

## Health Checks

- Manager API responds: `https://localhost:55000`
- Dashboard loads: `https://localhost`
- Host agent appears as active
- Alerts appear when `simulation/safe_ransomware_sim.py` is run

## Notes

- The compose file is intentionally single-node and presentation-oriented.
- Use prerecorded telemetry for the ransomware evidence portion of the demo.
- Do not use this environment to acquire or run real malware.
