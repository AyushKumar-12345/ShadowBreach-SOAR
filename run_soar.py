import json
import sys
from engine.orchestrator import SOAROrchestrator

def main():
    config_path = "config/soar_config.json"
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
    except Exception as e:
        sys.exit(f"Failed to load config: {e}")

    orchestrator = SOAROrchestrator(config)
    results = orchestrator.process_cycle()
    print(f"ShadowBreach-SOAR completed cycle. Processed {len(results)} incident(s).")
    for res in results:
        inc = res["incident"]
        print(f"[{inc['incident_id']}] Risk: {inc['risk_score']} | Severity: {inc['max_severity']} | Reports: {res['reports']['md_report']}")

if __name__ == "__main__":
    main()