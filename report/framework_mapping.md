# Framework Mapping

## NIST CSF 2.0

| Function | Demo Mapping |
|---|---|
| Govern | Documented roles, safe operating procedure, and evidence handling for the demo |
| Identify | Asset list includes host, Dockerized Wazuh services, datasets, and generated results |
| Protect | Live demo avoids malware detonation, uses controlled telemetry imports and scoped simulator output |
| Detect | Wazuh custom rules, alert review, metrics computation, and time-to-detect analysis |
| Respond | Analyst review of triggered alerts and documented triage steps during the presentation |
| Recover | Reset the demo target folder, retain reports and evidence, and restart the environment cleanly |

## ISO 27001:2022 Annex A

| Control | Demo Mapping |
|---|---|
| A.8.7 Protection against malware | Behavioral rules and monitoring logic show malware-oriented detection capability |
| A.8.15 Logging | Wazuh alert exports and simulator log ingestion provide auditable logging flow |
| A.8.16 Monitoring activities | Dashboard monitoring and alert triage are central to the live demonstration |
| A.5.24 Information security incident management planning and preparation | The demo defines a repeatable response flow and evidence collection process |
| A.8.13 Information backup | Results and sample metadata preserve reproducible analysis evidence |

## Positioning Statement

This demo should be described as a behavior-based detection prototype. It demonstrates monitoring, detection logic, and evidence analysis in a safe laboratory workflow without operationalizing live malware.
