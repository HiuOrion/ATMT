# Experiment Procedure

## Phase 1: Environment Preparation

1. Start Docker Desktop.
2. Run `docker compose -f infra/docker-compose.live.yml up -d`.
3. Run `powershell -ExecutionPolicy Bypass -File .\infra\configure_live_manager.ps1`.
4. Verify the Wazuh manager container is running and ready to monitor `runtime/replay/live_demo.jsonl`.

## Phase 2: Evidence Preparation

1. Store the public Lockbit source files under `data/public_sources/lockbit_ransomware/`.
2. Run `analysis/import_public_lockbit.py` to derive:
   - `data/benign_logs/alerts.csv`
   - `data/ransomware_logs/lockbit_public/alerts.csv`
   - `data/public_replay/lockbit_public.jsonl`
3. Confirm `metadata.json` exists under `data/ransomware_logs/lockbit_public/`.

## Phase 3: Analysis

1. Run the analysis pipeline:

```powershell
python analysis/evaluate.py --benign data/benign_logs --ransomware data/ransomware_logs --out results
```

2. Review:
   - `results/metrics_summary.csv`
   - `results/metrics_table.xlsx`
   - `results/detection_results.png`
   - `results/top_alerts.png`
   - `results/run_summary.md`

## Phase 4: Live Validation

1. Run the public replay script:

```powershell
python simulation/replay_public_lockbit.py --limit 10 --delay 0.5 --start-delay 1.0
```

2. Tail the Wazuh manager alerts:

```powershell
docker exec atmt-wazuh-manager-live tail -f /var/ossec/logs/alerts/alerts.json
```

3. Explain that this proves the live detection path while the public telemetry proves the analysis story.

## Phase 5: Reporting

1. Insert generated figures and metrics into the report.
2. Map the workflow to NIST CSF 2.0 and ISO 27001:2022.
3. Conclude with strengths, limitations, and safe future extensions.
