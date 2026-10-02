import subprocess
import platform
from typing import Dict, Any
from .base import BasePlaybook

class NetworkContainmentPlaybook(BasePlaybook):
    def __init__(self, rule_prefix: str = "ShadowBreach_Block_"):
        self.rule_prefix = rule_prefix
        self.os_type = platform.system()

    def execute(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        target_ip = incident.get("source_ip")
        if not target_ip:
            return {"status": "skipped", "reason": "No target IP found"}

        rule_name = f"{self.rule_prefix}{target_ip.replace('.', '_')}"
        
        if self.os_type == "Windows":
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=in",
                "action=block",
                f"remoteip={target_ip}"
            ]
        elif self.os_type == "Linux":
            cmd = ["iptables", "-A", "INPUT", "-s", target_ip, "-j", "DROP"]
        elif self.os_type == "Darwin":
            cmd = ["echo", f"block drop from {target_ip} to any"]
        else:
            return {"status": "failed", "reason": f"Unsupported OS: {self.os_type}"}

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if res.returncode == 0:
                return {"status": "success", "action": "blocked_ip", "ip": target_ip, "command": " ".join(cmd)}
            return {"status": "failed", "error": res.stderr.strip(), "command": " ".join(cmd)}
        except Exception as e:
            return {"status": "error", "error": str(e)}