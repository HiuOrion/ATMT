# ATMT Demo Guide

This guide explains how to run, present, and regenerate the ATMT Wazuh demo project for a class presentation.

## 1. What This Project Does

This project demonstrates behavior-based ransomware detection using:

- `Wazuh` running in `Docker Desktop`
- prerecorded ransomware-labeled telemetry for safe evidence replay
- a harmless local simulator that generates ransomware-like file activity
- a Python analysis pipeline that computes metrics and exports charts and a report

It does **not** run live malware.

## 2. Project Structure

Key folders:

- `infra/`: Docker and Wazuh setup
- `data/`: benign and ransomware-labeled sample alerts
- `analysis/`: metrics and chart generation
- `simulation/`: safe live-demo script
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

Generate the `.docx` report:

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

## 6. Start Wazuh In Docker

From the repo root:

```powershell
cd infra
docker compose up -d
docker compose ps
```

Validate the compose file first if needed:

```powershell
docker compose -f infra/docker-compose.yml config
```

Open the dashboard:

- `https://localhost`

## 7. Configure The Live Demo

To make the live simulator appear in Wazuh, the host Wazuh agent must watch:

- `simulation/output/demo_events.log`

Use the sample config in:

- `infra/wazuh/agent_localfile_example.xml`

Replace:

```text
REPLACE_WITH_ABSOLUTE_PATH_TO_DEMO_EVENTS_LOG
```

with:

```text
E:\Learn\Master degree\Documents\An toàn máy tính\ATMT\simulation\output\demo_events.log
```

The manager must also load:

- `infra/wazuh/custom_decoders/ransomware_demo_decoders.xml`
- `infra/wazuh/custom_rules/ransomware_demo_rules.xml`

After changing the host agent config, restart the Wazuh agent.

## 8. Run The Live Demo

From the repo root:

```powershell
python simulation/safe_ransomware_sim.py --output-dir simulation/output/demo_target --log-file simulation/output/demo_events.log --clean
```

This generates harmless demo events:

- `staging_complete`
- `mass_write`
- `mass_rename`

Expected Wazuh custom rule IDs:

- `100503`
- `100501`
- `100502`

## 9. Recommended Presentation Flow

1. Show the architecture and explain that the environment is safe and repeatable.
2. Show the exported metrics and charts in `results/`.
3. Show the final report in `report/ATMT_Wazuh_Demo_Report.pdf`.
4. Open Wazuh Dashboard and explain the custom rules.
5. Run the simulator live.
6. Refresh/search for the new alerts.
7. Finish with the NIST CSF 2.0 and ISO 27001:2022 mapping.

## 10. Useful Files During Class

- `results/run_summary.md`
- `results/detection_results.png`
- `results/top_alerts.png`
- `report/ATMT_Wazuh_Demo_Report.docx`
- `report/ATMT_Wazuh_Demo_Report.pdf`
- `report/framework_mapping.md`
- `report/presentation_notes.md`

## 11. Useful Dashboard Searches

Search by custom rule IDs:

```text
rule.id:100501 or rule.id:100502 or rule.id:100503
```

Search by demo text:

```text
demo_ransomware
```

## 12. Troubleshooting

If Docker starts but Wazuh does not load:

- run `docker compose ps`
- run `docker compose logs`
- confirm Docker Desktop is healthy

If the simulator runs but no Wazuh alert appears:

- confirm the host Wazuh agent is installed
- confirm the `localfile` path is correct
- confirm the manager has the demo decoder and rule files
- restart the agent and the manager
- check whether `simulation/output/demo_events.log` is being updated

If report export fails:

- rerun `python analysis/evaluate.py --benign data/benign_logs --ransomware data/ransomware_logs --out results`
- rerun `python report/export_report.py`

## 13. Safety Notes

- No live malware is included.
- No malware acquisition or execution steps are part of this repo.
- The simulator only creates and renames harmless local files in a demo folder.
- The prerecorded samples are evidence data only.
