# Safe Live Validation

This folder contains a harmless simulator that creates ransomware-like file activity in a dedicated folder and logs plain-text events for Wazuh ingestion.

## Example

```powershell
python simulation/safe_ransomware_sim.py --output-dir simulation/output/demo_target --log-file simulation/output/demo_events.log
```

## What It Does

- Creates a dedicated target directory
- Writes a burst of small text files
- Appends extra content to them
- Renames them to a locked-style extension
- Writes event lines to a log file that can be ingested by a Wazuh agent localfile configuration

## What It Does Not Do

- No encryption
- No deletion of backups or system state
- No persistence changes
- No privileged system changes
