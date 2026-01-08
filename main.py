#needs to be validated
from elastic.alerts import AlertFetcher
from elastic.context import AlertContext
from triage.classifier import AlertClassifier


def main():
    classifier = AlertClassifier(model="llama3.1:8b")
    fetcher = AlertFetcher()

    alerts = fetcher.fetch_recent_alerts()

    if not alerts:
        print("No active alerts found.")
        return

    for alert in alerts:
        context = AlertContext(alert).extract()
        decision = classifier.classify(context)

        print("=" * 80)
        print(f"Alert ID: {context['alert_id']}")
        print(f"Rule: {context['rule']['name']}")
        print(f"Host: {context['host']['hostname']}")
        print(f"Severity: {context['severity']}")
        print("--- AI TRIAGE DECISION ---")
        print(decision)


if __name__ == "__main__":
    main()
