# Demo Architecture

```mermaid
flowchart LR
    Host["Windows Host"] --> Docker["Docker Desktop"]
    Docker --> Manager["Wazuh Manager"]
    Docker --> Indexer["Wazuh Indexer"]
    Docker --> Dashboard["Wazuh Dashboard"]
    Host --> Agent["Wazuh Agent (Host)"]
    Agent --> Manager
    Replay["Prerecorded Ransomware Telemetry"] --> Analysis["Python Analysis Pipeline"]
    Analysis --> Results["Results and Report Figures"]
    Simulator["Safe File Activity Simulator"] --> Agent
    Dashboard --> Professor["Live Demo to Professor"]
    Results --> Professor
```

## Key Points

- The Wazuh stack is live in Docker Desktop.
- The ransomware evidence is replayed telemetry, not active malware.
- The live simulation is harmless and exists only to prove the detection path works in real time.
- The report combines dashboard evidence with computed metrics and standards mapping.
