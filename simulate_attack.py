import os
import json
import time
import subprocess
import sys

def setup_simulation_environment():
    os.makedirs("data/alerts", exist_ok=True)
    os.makedirs("data/quarantine", exist_ok=True)
    os.makedirs("data/reports", exist_ok=True)

    dummy_target = "data/quarantine_target.txt"
    with open(dummy_target, "w", encoding="utf-8") as f:
        f.write("CONFIDENTIAL DATA SIMULATION TARGET")

    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])

    attacker_ip = "198.51.100.42"

    nids_payload = [
        {
            "alert_id": "NIDS-ALERT-001",
            "timestamp": time.time(),
            "signature_name": "PORT_SCAN",
            "priority": "MEDIUM",
            "src_ip": attacker_ip,
            "dst_ip": "10.0.0.5"
        },
        {
            "alert_id": "NIDS-ALERT-002",
            "timestamp": time.time() + 1,
            "signature_name": "SYN_FLOOD",
            "priority": "HIGH",
            "src_ip": attacker_ip,
            "dst_ip": "10.0.0.5"
        }
    ]

    edr_payload = [
        {
            "alert_id": "EDR-ALERT-001",
            "timestamp": time.time() + 2,
            "detection_type": "ENTROPY_RANSOMWARE",
            "severity": "CRITICAL",
            "network_context": {
                "remote_ip": attacker_ip
            },
            "process": {
                "pid": proc.pid,
                "name": "python_dummy_ransom.exe"
            },
            "file_target": {
                "path": os.path.abspath(dummy_target)
            }
        }
    ]

    with open("data/alerts/nids_alerts.json", "w", encoding="utf-8") as f:
        json.dump(nids_payload, f, indent=2)

    with open("data/alerts/canary_alerts.json", "w", encoding="utf-8") as f:
        json.dump(edr_payload, f, indent=2)

    print(f"Simulation configured.")
    print(f"  Rogue Process Spawned PID: {proc.pid}")
    print(f"  Target File: {dummy_target}")
    print(f"  Simulated Attacker IP: {attacker_ip}")

if __name__ == "__main__":
    setup_simulation_environment()