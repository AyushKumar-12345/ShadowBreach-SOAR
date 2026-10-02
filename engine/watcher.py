import os
import time
from typing import Dict, Any
from engine.orchestrator import SOAROrchestrator

class TelemetryWatcher:
    def __init__(self, orchestrator: SOAROrchestrator, poll_interval: float = 1.0):
        self.orchestrator = orchestrator
        self.poll_interval = poll_interval
        self.edr_path = orchestrator.config["log_sources"]["edr_path"]
        self.nids_path = orchestrator.config["log_sources"]["nids_path"]
        self.last_mtimes = {}

    def _get_mtime(self, path: str) -> float:
        return os.path.getmtime(path) if os.path.exists(path) else 0.0

    def start(self):
        self.last_mtimes[self.edr_path] = self._get_mtime(self.edr_path)
        self.last_mtimes[self.nids_path] = self._get_mtime(self.nids_path)
        print("[*] ShadowBreach daemon started. Watching telemetry feeds...")

        try:
            while True:
                edr_mtime = self._get_mtime(self.edr_path)
                nids_mtime = self._get_mtime(self.nids_path)

                changed = False
                if edr_mtime > self.last_mtimes[self.edr_path]:
                    self.last_mtimes[self.edr_path] = edr_mtime
                    changed = True
                if nids_mtime > self.last_mtimes[self.nids_path]:
                    self.last_mtimes[self.nids_path] = nids_mtime
                    changed = True

                if changed:
                    print("[+] Change detected in alert stream. Executing orchestration cycle...")
                    results = self.orchestrator.process_cycle()
                    for r in results:
                        inc = r["incident"]
                        print(f"    [ALERT] {inc['incident_id']} | Risk Score: {inc['risk_score']} | Source IP: {inc.get('source_ip')}")

                time.sleep(self.poll_interval)
        except KeyboardInterrupt:
            print("\n[*] Daemon stopped by operator.")