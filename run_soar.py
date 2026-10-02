import sys
import json
import argparse
from engine.orchestrator import SOAROrchestrator
from engine.watcher import TelemetryWatcher

def main():
    parser = argparse.ArgumentParser(description="ShadowBreach SOAR Engine")
    parser.add_argument("--daemon", action="store_true", help="Run in continuous monitoring daemon mode")
    args = parser.parse_args()

    config_path = "config/soar_config.json"
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
    except Exception as e:
        sys.exit(f"Failed to load config: {e}")

    orchestrator = SOAROrchestrator(config)

    if args.daemon:
        watcher = TelemetryWatcher(orchestrator)
        watcher.start()
    else:
        results = orchestrator.process_cycle()
        print(f"ShadowBreach-SOAR completed batch cycle. Processed {len(results)} incident(s).")
        for res in results:
            inc = res["incident"]
            print(f"[{inc['incident_id']}] Risk: {inc['risk_score']} | Severity: {inc['max_severity']} | Report: {res['reports']['md_report']}")

if __name__ == "__main__":
    main()