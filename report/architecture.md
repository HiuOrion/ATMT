# Demo Architecture

```mermaid
flowchart LR
    Host["Windows Host"] --> Docker["Docker Desktop"]
    Docker --> Manager["Wazuh Manager (Live Demo)"]
    Replay["Public Lockbit Sysmon Source"] --> Analysis["Python Analysis Pipeline"]
    Analysis --> Results["Results and Report Figures"]
    Replay --> Derived["Derived JSON Replay"]
    Derived --> Manager
    Manager --> Professor["Live Demo to Professor"]
    Results --> Professor
```

## Key Points

- The Wazuh manager is live in Docker Desktop.
- The ransomware evidence is derived from a public Lockbit telemetry source, not from active malware.
- The live replay exists to prove the detection path works in real time without malware execution.
- The report combines dashboard evidence with computed metrics and standards mapping.
