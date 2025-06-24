# LockBit 3.0 Threat Detection Lab

## Overview

This lab helps you build a LockBit ransomware threat detection environment based on MITRE ATT&CK and Sigma rules. It includes detection rules, ingestion pipelines, hunting queries, dashboards, and red team simulation scripts.

## Setup

### 1. Deploy Log Collection

- Install Sysmon and Winlogbeat on your Windows endpoints.
- Configure `pipelines/winlogbeat.yml` and start Winlogbeat to ship logs to your SIEM.

### 2. Ingest Logs and Setup Dashboards

- Load dashboards from `dashboards/lockbit3_kibana_dashboard.json` into Kibana.
- Configure Logstash pipeline (`pipelines/logstash.conf`) to parse and enrich logs.

### 3. Deploy Detection Rules

- Convert Sigma rules with [sigma-cli](https://github.com/SigmaHQ/sigma) and import to your SIEM.
- Example to convert and test rule locally:

```powershell
.\scripts\sigma_convert_and_test.ps1 detection_rules\lockbit3_sigma.yml
```

### 4. Run Red Team Simulation

- Use `simulation_scripts/lockbit3_simulation.bat` or `.ps1` on a test machine.
- Monitor generated artifacts and alerts in your SIEM.

### 5. Hunt and Investigate

- Use hunting queries in `hunting_queries/lockbit3_hunting_kql.query`.
- Review detection alerts and pivot on suspicious activity.

## Contributing

Feel free to submit PRs to improve detection rules, simulations, and docs!
