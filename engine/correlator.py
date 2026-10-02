import uuid
from typing import List, Dict, Any
from .risk_engine import RiskEngine

class AlertCorrelator:
    def __init__(self, time_window_seconds: int = 120):
        self.time_window = time_window_seconds
        self.risk_engine = RiskEngine()

    def correlate(self, normalized_alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        ip_groups: Dict[str, List[Dict[str, Any]]] = {}

        for alert in normalized_alerts:
            src_ip = alert.get("source_ip") or "LOCAL_HOST"
            ip_groups.setdefault(src_ip, []).append(alert)

        incidents = []

        for src_ip, alerts in ip_groups.items():
            alerts_sorted = sorted(alerts, key=lambda x: x["timestamp"])
            pids = list({a["pid"] for a in alerts_sorted if a.get("pid") is not None})
            files = list({a["file_path"] for a in alerts_sorted if a.get("file_path") is not None})
            threat_types = [a["threat_type"] for a in alerts_sorted]
            severities = [a["severity"] for a in alerts_sorted]

            severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
            max_severity = max(severities, key=lambda s: severity_order.get(s, 0)) if severities else "LOW"

            intel = self.risk_engine.evaluate(threat_types, max_severity)

            incident = {
                "incident_id": f"INC-{str(uuid.uuid4())[:8].upper()}",
                "source_ip": src_ip if src_ip != "LOCAL_HOST" else None,
                "process_ids": pids,
                "file_paths": files,
                "threat_types": threat_types,
                "max_severity": max_severity,
                "risk_score": intel["risk_score"],
                "mitre_tactics": intel["tactics"],
                "mitre_techniques": intel["techniques"],
                "alert_count": len(alerts_sorted),
                "alerts": alerts_sorted
            }
            incidents.append(incident)

        return incidents