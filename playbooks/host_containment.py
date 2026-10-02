import os
import shutil
import psutil
from typing import Dict, Any, List
from .base import BasePlaybook

class HostContainmentPlaybook(BasePlaybook):
    def __init__(self, quarantine_dir: str = "data/quarantine"):
        self.quarantine_dir = quarantine_dir
        os.makedirs(self.quarantine_dir, exist_ok=True)

    def execute(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        results = {
            "processes_terminated": [],
            "files_quarantined": [],
            "errors": []
        }

        pids = incident.get("process_ids", [])
        for pid in pids:
            try:
                if psutil.pid_exists(pid):
                    proc = psutil.Process(pid)
                    children = proc.children(recursive=True)
                    for child in children:
                        child.kill()
                    proc.kill()
                    psutil.wait_procs(children + [proc], timeout=3)
                    results["processes_terminated"].append(pid)
            except Exception as e:
                results["errors"].append({"pid": pid, "error": str(e)})

        file_paths = incident.get("file_paths", [])
        for fpath in file_paths:
            if os.path.exists(fpath):
                try:
                    fname = os.path.basename(fpath)
                    dest = os.path.join(self.quarantine_dir, f"{fname}.quarantine")
                    shutil.move(fpath, dest)
                    results["files_quarantined"].append({"original": fpath, "quarantined_to": dest})
                except Exception as e:
                    results["errors"].append({"file": fpath, "error": str(e)})

        return {"status": "completed", "details": results}