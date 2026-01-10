from dotenv import load_dotenv
from elastic.alerts import AlertFetcher
from elastic.context import AlertContext
from triage.classifier import AlertClassifier

# Load environment variables from .env file
load_dotenv()


def main():
    classifier = AlertClassifier(model="deepseek-r1:8b")
    fetcher = AlertFetcher()

    alerts = fetcher.fetch_recent_alerts()

    if not alerts:
        print("No active alerts found.")
        return

    for alert in alerts:
        context = AlertContext(alert).extract()
        
        decision = classifier.classify_with_tools(context)

        print("=" * 80)
        print(f"Alert ID: {context['alert_id']}")
        print(f"Rule: {context['rule']['name']}")
        print(f"Host: {context['host']['hostname']}")
        print(f"Severity: {context['severity']}")
        print("--- AI TRIAGE DECISION ---")
        # Create a display-friendly version of the decision
        display_decision = decision.copy()
        if 'investigation_history' in display_decision:
            # Clean up raw logs in history for cleaner terminal output
            for item in display_decision['investigation_history']:
                if 'result' in item and 'logs' in item['result']:
                    log_count = len(item['result']['logs'])
                    item['result']['logs'] = f"<{log_count} logs - hidden for brevity>"
        
        import json
        print(json.dumps(display_decision, indent=2, default=str))


if __name__ == "__main__":
    main()
