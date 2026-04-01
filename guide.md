# ATMT Demo Guide

This guide explains how to run, present, and regenerate the ATMT Wazuh demo project for a class presentation using a public Lockbit dataset and a Dockerized Wazuh live replay.

## 1. What This Project Does

This project demonstrates behavior-based ransomware detection using:

- `Wazuh` running in `Docker Desktop`
- Splunk's public Lockbit Sysmon dataset as the evidence source
- a replay script that streams derived public events into Wazuh
- a Python analysis pipeline that computes metrics and exports charts and a report

It does **not** run live malware.

## 2. Project Structure

Key folders:

- `infra/`: Docker and Wazuh setup
- `data/`: benign and ransomware-labeled sample alerts
- `analysis/`: metrics and chart generation
- `simulation/`: public replay live-demo script
- `results/`: generated outputs
- `report/`: exported report and report generator

## 3. Requirements

Install:

- `Python 3.11+`
- `Docker Desktop`
- optional: `Microsoft Word` if you want PDF export through Word automation

Python packages:

```powershell
python -m pip install -r requirements.txt
```

## 4. Generate Results

From the repo root:

```powershell
python analysis/evaluate.py --benign data/benign_logs --ransomware data/ransomware_logs --out results
```

This generates:

- `results/metrics_summary.csv`
- `results/metrics_table.xlsx`
- `results/detection_results.png`
- `results/top_alerts.png`
- `results/run_summary.md`

## 5. Export The Report

Build the public dataset first:

```powershell
python analysis/import_public_lockbit.py --source-log data/public_sources/lockbit_ransomware/public_lockbit_sysmon.log --source-meta data/public_sources/lockbit_ransomware/public_lockbit_source.yml --data-root data
```

Then generate the `.docx` report:

```powershell
python report/export_report.py
```

This writes:

- `report/ATMT_Wazuh_Demo_Report.docx`

If Microsoft Word is installed, you can export a PDF with PowerShell:

```powershell
$docx = (Resolve-Path 'report\ATMT_Wazuh_Demo_Report.docx').Path
$pdf = Join-Path (Get-Location) 'report\ATMT_Wazuh_Demo_Report.pdf'
$word = New-Object -ComObject Word.Application
$word.Visible = $false
$document = $word.Documents.Open($docx)
$wdExportFormatPDF = 17
$document.ExportAsFixedFormat($pdf, $wdExportFormatPDF)
$document.Close()
$word.Quit()
```

## 6. Start The Tested Live Docker Demo

The tested live path for this project is the manager-only compose file:

From the repo root:

```powershell
docker compose -f infra/docker-compose.live.yml up -d
powershell -ExecutionPolicy Bypass -File .\infra\configure_live_manager.ps1
docker compose -f infra/docker-compose.live.yml ps
```

Show live alerts:

```powershell
python simulation/replay_public_lockbit.py --limit 8 --delay 0.5 --start-delay 1.0
docker exec atmt-wazuh-manager-live tail -n 30 /var/ossec/logs/alerts/alerts.json
```

This path was chosen because it is lightweight and reliable for classroom demonstration.

## 7. Optional Full Stack Compose

The repo still includes `infra/docker-compose.yml` if you want to experiment with a fuller Wazuh stack, but the manager-only compose is the recommended live demo path.

## 8. Public Source

Public source used in this repo:

- `https://github.com/splunk/attack_data/tree/master/datasets/malware/lockbit_ransomware`

The raw source files are copied into:

- `data/public_sources/lockbit_ransomware/`

## 9. Live Replay Files

Replay source:

- `data/public_replay/lockbit_public.jsonl`

Live file consumed by Dockerized Wazuh:

- `runtime/replay/live_demo.jsonl`

Expected Wazuh custom rule IDs:

- `100610`
- `100611`
- `100612`
- `100613`
- `100614`

## 10. Recommended Presentation Flow

1. Show the architecture and explain that the environment is safe and repeatable.
2. State that the ransomware evidence comes from Splunk's public Lockbit Sysmon dataset.
3. Show the exported metrics and charts in `results/`.
4. Show the final report in `report/ATMT_Wazuh_Demo_Report.pdf`.
5. Start the live Docker manager if it is not already running.
6. Replay 8-12 public Lockbit-derived events live.
7. Tail `alerts.json` from the Wazuh container and point out the rule IDs and descriptions.
8. Finish with the NIST CSF 2.0 and ISO 27001:2022 mapping.

## 11. Useful Files During Class

- `results/run_summary.md`
- `results/detection_results.png`
- `results/top_alerts.png`
- `report/ATMT_Wazuh_Demo_Report.docx`
- `report/ATMT_Wazuh_Demo_Report.pdf`
- `report/framework_mapping.md`
- `report/presentation_notes.md`

## 12. Useful Live Commands

Start the live manager:

```powershell
docker compose -f infra/docker-compose.live.yml up -d
powershell -ExecutionPolicy Bypass -File .\infra\configure_live_manager.ps1
```

Replay public Lockbit events:

```powershell
python simulation/replay_public_lockbit.py --limit 10 --delay 0.5 --start-delay 1.0
```

Watch Wazuh alerts:

```powershell
docker exec atmt-wazuh-manager-live tail -f /var/ossec/logs/alerts/alerts.json
```

Inspect replay file:

```powershell
Get-Content runtime\replay\live_demo.jsonl
```

## 13. Useful Alert Filters

Search by custom rule IDs in the tailed JSON:

```text
100610, 100611, 100612, 100613, 100614
```

## 14. Troubleshooting

If Docker starts but Wazuh does not load:

- run `docker compose -f infra/docker-compose.live.yml ps`
- run `docker compose -f infra/docker-compose.live.yml logs`
- confirm Docker Desktop is healthy

If the replay runs but no Wazuh alert appears:

- confirm `runtime/replay/live_demo.jsonl` is being written
- confirm the container is running
- rerun `powershell -ExecutionPolicy Bypass -File .\infra\configure_live_manager.ps1`
- confirm the custom rule exists inside the container with `docker exec atmt-wazuh-manager-live ls /var/ossec/etc/rules`
- do not use `--truncate` after the manager is already watching the file; rerun the configure script first if you need a clean replay file
- restart the manager container and replay again

If report export fails:

- rerun `python analysis/import_public_lockbit.py --source-log data/public_sources/lockbit_ransomware/public_lockbit_sysmon.log --source-meta data/public_sources/lockbit_ransomware/public_lockbit_source.yml --data-root data`
- rerun `python analysis/evaluate.py --benign data/benign_logs --ransomware data/ransomware_logs --out results`
- rerun `python report/export_report.py`

## 15. Safety Notes

- No live malware is included.
- No malware acquisition or execution steps are part of this repo.
- The public Lockbit source is read-only telemetry.
- The live demo replays derived JSON events into Dockerized Wazuh.
