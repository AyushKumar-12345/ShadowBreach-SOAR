import time
from typing import Dict, Any

class TelemetryNormalizer:
    @staticmethod
    def normalize_edr(alert: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": alert.get("alert_id", f"EDR-{int(time.time() * 1000)}"),
            "source": "CanaryGuard-EDR",
            "timestamp": alert.get("timestamp", time.time()),
            "threat_type": alert.get("detection_type", "unknown_edr"),
            "severity": alert.get("severity", "LOW").upper(),
            "source_ip": alert.get("network_context", {}).get("remote_ip"),
            "pid": alert.get("process", {}).get("pid"),
            "process_name": alert.get("process", {}).get("name"),
            "file_path": alert.get("file_target", {}).get("path"),
            "raw_payload": alert
        }

    @staticmethod
    def normalize_nids(alert: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": alert.get("alert_id", f"NIDS-{int(time.time() * 1000)}"),
            "source": "NetSentry-NIDS",
            "timestamp": alert.get("timestamp", time.time()),
            "threat_type": alert.get("signature_name", "unknown_nids"),
            "severity": alert.get("priority", "LOW").upper(),
            "source_ip": alert.get("src_ip"),
            "destination_ip": alert.get("dst_ip"),
            "pid": alert.get("associated_pid"),
            "process_name": None,
            "file_path": None,
            "raw_payload": alert
        }