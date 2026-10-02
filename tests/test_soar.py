import os
import json
import unittest
from engine.normalizer import TelemetryNormalizer
from engine.risk_engine import RiskEngine
from engine.correlator import AlertCorrelator
from playbooks.host_containment import HostContainmentPlaybook

class TestShadowBreachSOAR(unittest.TestCase):
    def setUp(self):
        self.test_dir = "tests/tmp"
        os.makedirs(self.test_dir, exist_ok=True)

    def tearDown(self):
        if os.path.exists(self.test_dir):
            for f in os.listdir(self.test_dir):
                os.remove(os.path.join(self.test_dir, f))
            os.rmdir(self.test_dir)

    def test_normalization_edr(self):
        raw = {
            "alert_id": "EDR-100",
            "timestamp": 123456789.0,
            "detection_type": "CANARY_FILE_TRIP",
            "severity": "CRITICAL",
            "process": {"pid": 4321, "name": "bad.exe"},
            "file_target": {"path": "/tmp/canary.txt"}
        }
        normalized = TelemetryNormalizer.normalize_edr(raw)
        self.assertEqual(normalized["id"], "EDR-100")
        self.assertEqual(normalized["threat_type"], "CANARY_FILE_TRIP")
        self.assertEqual(normalized["pid"], 4321)
        self.assertEqual(normalized["file_path"], "/tmp/canary.txt")

    def test_normalization_nids(self):
        raw = {
            "alert_id": "NIDS-200",
            "timestamp": 123456789.0,
            "signature_name": "SYN_FLOOD",
            "priority": "HIGH",
            "src_ip": "192.168.1.50",
            "dst_ip": "192.168.1.1"
        }
        normalized = TelemetryNormalizer.normalize_nids(raw)
        self.assertEqual(normalized["id"], "NIDS-200")
        self.assertEqual(normalized["source_ip"], "192.168.1.50")
        self.assertEqual(normalized["threat_type"], "SYN_FLOOD")

    def test_risk_engine_calculation(self):
        risk_engine = RiskEngine()
        res = risk_engine.evaluate(["SYN_FLOOD", "ENTROPY_RANSOMWARE"], "CRITICAL")
        self.assertGreaterEqual(res["risk_score"], 70)
        self.assertIn("Impact", res["tactics"])

    def test_alert_correlator(self):
        correlator = AlertCorrelator()
        alerts = [
            {
                "id": "A1",
                "source": "NIDS",
                "timestamp": 100,
                "threat_type": "PORT_SCAN",
                "severity": "MEDIUM",
                "source_ip": "10.10.10.10",
                "pid": None,
                "file_path": None
            },
            {
                "id": "A2",
                "source": "EDR",
                "timestamp": 102,
                "threat_type": "ENTROPY_RANSOMWARE",
                "severity": "CRITICAL",
                "source_ip": "10.10.10.10",
                "pid": 9999,
                "file_path": "/tmp/test"
            }
        ]
        incidents = correlator.correlate(alerts)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["source_ip"], "10.10.10.10")
        self.assertEqual(incidents[0]["process_ids"], [9999])
        self.assertGreaterEqual(incidents[0]["risk_score"], 70)

    def test_host_containment_quarantine(self):
        test_file = os.path.join(self.test_dir, "malicious.bin")
        with open(test_file, "w") as f:
            f.write("payload")

        playbook = HostContainmentPlaybook(quarantine_dir=self.test_dir)
        incident = {"process_ids": [], "file_paths": [test_file]}
        result = playbook.execute(incident)

        self.assertEqual(result["status"], "completed")
        self.assertFalse(os.path.exists(test_file))
        self.assertTrue(os.path.exists(f"{test_file}.quarantine"))

if __name__ == "__main__":
    unittest.main()