# Experiment Procedure

## Phase 1: Environment Preparation

1. Start Docker Desktop.
2. Run `docker compose up -d` from `infra/`.
3. Verify the Wazuh dashboard and manager API are reachable.
4. Ensure the host Wazuh agent is active and configured to monitor the simulator log file.

## Phase 2: Evidence Preparation

1. Place benign alert exports under `data/benign_logs/`.
2. Place ransomware-labeled telemetry samples under `data/ransomware_logs/<sample_name>/`.
3. Confirm every sample contains `alerts.csv` and `metadata.json`.

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

1. Run the safe simulator:

```powershell
python simulation/safe_ransomware_sim.py --output-dir simulation/output/demo_target --log-file simulation/output/demo_events.log --clean
```

2. Show the Wazuh dashboard receiving the custom demo alerts.
3. Explain that this proves the live detection path while the prerecorded telemetry proves the analysis story.

## Phase 5: Reporting

1. Insert generated figures and metrics into the report.
2. Map the workflow to NIST CSF 2.0 and ISO 27001:2022.
3. Conclude with strengths, limitations, and safe future extensions.
