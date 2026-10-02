import os
import json
from datetime import datetime
from typing import Dict, Any

class IncidentReporter:
    def __init__(self, output_dir: str = "data/reports"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def generate(self, incident: Dict[str, Any], playbook_results: Dict[str, Any]) -> Dict[str, str]:
        inc_id = incident["incident_id"]
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")

        report_payload = {
            "incident_id": inc_id,
            "generated_at": timestamp,
            "incident_data": incident,
            "playbook_results": playbook_results
        }

        json_path = os.path.join(self.output_dir, f"{inc_id}.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report_payload, f, indent=2)

        md_content = f"""# Executive Incident Report: {inc_id}
**Classification:** HIGH RISK / AUTONOMOUS CONTAINMENT  
**Generated At:** {timestamp}  
**Risk Score:** {incident['risk_score']} / 100  
**Overall Severity:** {incident['max_severity']}  

---

## 1. Executive Summary
An automated detection correlation triggered autonomous containment response. The target source IP `{incident.get('source_ip') or 'N/A'}` was involved in `{incident['alert_count']}` distinct alert telemetry events matching MITRE tactics: {', '.join(incident['mitre_tactics'])}.

## 2. MITRE ATT&CK Mapping
| Technique ID | Technique Name | Tactic |
|---|---|---|
"""
        for t in incident["mitre_techniques"]:
            md_content += f"| {t['id']} | {t['name']} | {t['tactic']} |\n"

        md_content += f"""
## 3. Autonomous Containment Actions
- **Network Enforcement:** {json.dumps(playbook_results.get('network', {}), indent=2)}
- **Host Process & Quarantine:** {json.dumps(playbook_results.get('host', {}), indent=2)}

## 4. Correlated Telemetry Details
- **Associated PIDs:** {incident['process_ids']}
- **Flagged File Targets:** {incident['file_paths']}
- **Threat Signatures:** {', '.join(incident['threat_types'])}
"""
        md_path = os.path.join(self.output_dir, f"{inc_id}.md")
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md_content)

        return {"json_report": json_path, "md_report": md_path}