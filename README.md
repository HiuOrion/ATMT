# ATMT Wazuh Demo Toolkit

This repository implements a safe, repeatable ransomware-detection demo for a professor presentation. It uses public Lockbit telemetry from Splunk's `attack_data` repository for the evidence set, a Dockerized Wazuh manager for the live alert path, and replay scripts that avoid running malware.

## What Is Included

- `infra/`: Docker and Wazuh operator assets
- `data/`: public-source telemetry, derived analysis inputs, and replay artifacts
- `analysis/`: Python analysis pipeline for metrics and charts
- `simulation/`: replay scripts for a live alert demo
- `report/`: report scaffold, mappings, and presentation assets
- `tests/`: unit and integration coverage for the analysis code

## Quick Start

1. Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

2. Build the public Lockbit-derived dataset:

```powershell
python analysis/import_public_lockbit.py --source-log data/public_sources/lockbit_ransomware/public_lockbit_sysmon.log --source-meta data/public_sources/lockbit_ransomware/public_lockbit_source.yml --data-root data
```

3. Generate analysis outputs:

```powershell
python analysis/evaluate.py --benign data/benign_logs --ransomware data/ransomware_logs --out results
```

4. Export the report:

```powershell
python report/export_report.py
```

5. Run the test suite:

```powershell
pytest
```

## Public Source

The ransomware evidence is derived from Splunk's public Lockbit Sysmon dataset:

- Source page: <https://github.com/splunk/attack_data/tree/master/datasets/malware/lockbit_ransomware>
- Dataset metadata is stored under `data/public_sources/lockbit_ransomware/`

The repo converts that raw Sysmon log into:

- `data/benign_logs/alerts.csv` for background baseline rows
- `data/ransomware_logs/lockbit_public/alerts.csv` for suspicious rows
- `data/public_replay/lockbit_public.jsonl` for Docker live replay

## Live Docker Demo

The tested live path is the manager-only Wazuh compose file:

```powershell
docker compose -f infra/docker-compose.live.yml up -d
python simulation/replay_public_lockbit.py --truncate
docker exec atmt-wazuh-manager-live tail -n 20 /var/ossec/logs/alerts/alerts.json
```

This produces live alerts inside the Dockerized Wazuh manager without needing live malware or a host Wazuh agent.

## Safety

- No live malware execution is implemented or documented in this repository.
- The public Lockbit source is treated as read-only telemetry.
- The live demo replays derived JSON events into Wazuh and does not detonate malware.
