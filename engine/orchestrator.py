from typing import Dict, Any, List
from .ingestor import TelemetryIngestor
from .normalizer import TelemetryNormalizer
from .correlator import AlertCorrelator
from .reporter import IncidentReporter
from playbooks.network_containment import NetworkContainmentPlaybook
from playbooks.host_containment import HostContainmentPlaybook

class SOAROrchestrator:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.ingestor = TelemetryIngestor(
            config["log_sources"]["edr_path"],
            config["log_sources"]["nids_path"]
        )
        self.normalizer = TelemetryNormalizer()
        self.correlator = AlertCorrelator()
        self.risk_threshold = config["containment"]["risk_score_containment_threshold"]
        self.net_playbook = NetworkContainmentPlaybook(
            rule_prefix=config["containment"]["firewall_rule_prefix"]
        )
        self.host_playbook = HostContainmentPlaybook(
            quarantine_dir=config["containment"]["quarantine_dir"]
        )
        self.reporter = IncidentReporter(
            output_dir=config["reporting"]["output_dir"]
        )

    def process_cycle(self) -> List[Dict[str, Any]]:
        raw = self.ingestor.fetch_all()
        normalized = []
        for e in raw["edr"]:
            normalized.append(self.normalizer.normalize_edr(e))
        for n in raw["nids"]:
            normalized.append(self.normalizer.normalize_nids(n))

        incidents = self.correlator.correlate(normalized)
        executed_incidents = []

        for incident in incidents:
            playbook_results = {"network": None, "host": None}
            if incident["risk_score"] >= self.risk_threshold:
                if incident.get("source_ip"):
                    playbook_results["network"] = self.net_playbook.execute(incident)
                if incident.get("process_ids") or incident.get("file_paths"):
                    playbook_results["host"] = self.host_playbook.execute(incident)

            reports = self.reporter.generate(incident, playbook_results)
            executed_incidents.append({
                "incident": incident,
                "containment": playbook_results,
                "reports": reports
            })

        return executed_incidents