from typing import Dict, Any, List

class RiskEngine:
    MITRE_CATALOG = {
        "SYN_FLOOD": {"tactic": "Impact", "technique_id": "T1498", "technique_name": "Network Denial of Service", "base_score": 30},
        "PORT_SCAN": {"tactic": "Discovery", "technique_id": "T1046", "technique_name": "Network Service Discovery", "base_score": 20},
        "ARP_SPOOF": {"tactic": "Credential Access", "technique_id": "T1557", "technique_name": "Adversary-in-the-Middle", "base_score": 40},
        "CANARY_FILE_TRIP": {"tactic": "Defense Evasion", "technique_id": "T1070", "technique_name": "Indicator Removal", "base_score": 45},
        "ENTROPY_RANSOMWARE": {"tactic": "Impact", "technique_id": "T1486", "technique_name": "Data Encrypted for Impact", "base_score": 50},
        "INTEGRITY_VIOLATION": {"tactic": "Persistence", "technique_id": "T1554", "technique_name": "Compromise Client Software Binary", "base_score": 35}
    }

    SEVERITY_WEIGHTS = {
        "CRITICAL": 1.5,
        "HIGH": 1.25,
        "MEDIUM": 1.0,
        "LOW": 0.5
    }

    def evaluate(self, threat_types: List[str], max_severity: str) -> Dict[str, Any]:
        total_score = 0.0
        tactics = set()
        techniques = []

        for threat in threat_types:
            entry = self.MITRE_CATALOG.get(threat, {
                "tactic": "Initial Access",
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "base_score": 15
            })
            total_score += entry["base_score"]
            tactics.add(entry["tactic"])
            techniques.append({
                "id": entry["technique_id"],
                "name": entry["technique_name"],
                "tactic": entry["tactic"]
            })

        multiplier = self.SEVERITY_WEIGHTS.get(max_severity, 1.0)
        calculated_score = min(int(total_score * multiplier), 100)

        return {
            "risk_score": calculated_score,
            "tactics": list(tactics),
            "techniques": techniques
        }