# ATMT Wazuh Demo Toolkit

This repository implements a safe, repeatable ransomware-detection demo for a professor presentation. It uses a Dockerized Wazuh stack, prerecorded telemetry for "real" ransomware evidence, and a harmless local simulator that produces ransomware-like file activity for live validation.

## What Is Included

- `infra/`: Docker and Wazuh operator assets
- `data/`: sample benign and ransomware-labeled alert exports plus metadata
- `analysis/`: Python analysis pipeline for metrics and charts
- `simulation/`: safe behavior generator for a live alert demo
- `report/`: report scaffold, mappings, and presentation assets
- `tests/`: unit and integration coverage for the analysis code

## Quick Start

1. Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

2. Generate analysis outputs from the sample data:

```powershell
python analysis/evaluate.py --benign data/benign_logs --ransomware data/ransomware_logs --out results
```

3. Run the test suite:

```powershell
pytest
```

## Safety

- No live malware execution is implemented or documented in this repository.
- The safe simulator only creates, updates, and renames harmless test files in a controlled folder.
- Any prerecorded ransomware evidence must be collected outside this repo and treated as read-only telemetry.
