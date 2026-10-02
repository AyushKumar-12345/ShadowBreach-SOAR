import json
import os
from typing import List, Dict, Any

class TelemetryIngestor:
    def __init__(self, edr_path: str, nids_path: str):
        self.edr_path = edr_path
        self.nids_path = nids_path

    def _read_file(self, path: str) -> List[Dict[str, Any]]:
        if not os.path.exists(path):
            return []
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, list) else [data]
        except Exception:
            return []

    def fetch_all(self) -> Dict[str, List[Dict[str, Any]]]:
        return {
            "edr": self._read_file(self.edr_path),
            "nids": self._read_file(self.nids_path)
        }