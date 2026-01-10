from elastic.client import ElasticClient


class AlertFetcher:
    def __init__(self):          ##This fetches the client.py file to get an established connection with elastic siem.
        self.client = ElasticClient()
        self.alert_index = ".alerts-security.alerts-*"

    def fetch_recent_alerts(self, minutes=1440, size=1): ##This fetches alerts in the last 10 minutes size set to 1 for test, in an actual environment you'll want to expand this. 
        query = {
            "size": size,
            "sort": [
                {
                    "@timestamp": {
                        "order": "desc"
                    }
                }
            ],
            "query": {
                "bool": {
                    "filter": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": f"now-{minutes}m"
                                }
                            }
                        },
                        {
                            "term": {
                                "kibana.alert.workflow_status": "open"
                            }
                        }
                    ]
                }
            }
        }

        response = self.client.post(
            f"/{self.alert_index}/_search",
            query
        )

        return response.get("hits", {}).get("hits", [])

if __name__ == "__main__":
    import json
    try:
        fetcher = AlertFetcher()
        alerts = fetcher.fetch_recent_alerts()
        print(json.dumps(alerts, indent=2))
    except Exception as e:
        print(f"Error fetching alerts: {e}")
