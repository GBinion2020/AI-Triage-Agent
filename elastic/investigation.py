from datetime import datetime, timedelta
from typing import Dict, Any, List
from elastic.client import ElasticClient


class HostLogSearcher:
    """Tool for investigating host logs around a specific time."""
    
    def __init__(self):
        self.client = ElasticClient()
        # Default logs index pattern
        self.log_index = "logs-*"

    def search_host_logs(self, host_name: str, alert_timestamp: str, window_minutes: int = 15, direction: str = "BEFORE") -> Dict[str, Any]:
        """
        Search for logs related to a specific host in a time window relative to the alert.
        """
        # Validate input
        window_minutes = min(max(1, window_minutes), 60)  # Max 1 hour
        
        try:
            # Parse alert timestamp
            # Elastic usually returns ISO format like: 2026-01-10T05:56:54.814Z
            dt_format = "%Y-%m-%dT%H:%M:%S.%fZ"
            # Some timestamps might not have decimal seconds
            if "." not in alert_timestamp:
                dt_format = "%Y-%m-%dT%H:%M:%SZ"
                
            alert_dt = datetime.strptime(alert_timestamp, dt_format)
            
            # Calculate time range
            if direction == "BEFORE":
                start_dt = alert_dt - timedelta(minutes=window_minutes)
                end_dt = alert_dt
            elif direction == "AFTER":
                start_dt = alert_dt
                end_dt = alert_dt + timedelta(minutes=window_minutes)
            else:  # CENTERED
                start_dt = alert_dt - timedelta(minutes=window_minutes // 2)
                end_dt = alert_dt + timedelta(minutes=window_minutes // 2)
                
            start_iso = start_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
            end_iso = end_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

            # Construct query - pull all fields for visibility
            query = {
                "size": 50,
                "sort": [{"@timestamp": {"order": "desc"}}],
                "query": {
                    "bool": {
                        "filter": [
                            {"term": {"host.name": host_name}},
                            {
                                "range": {
                                    "@timestamp": {
                                        "gte": start_iso,
                                        "lte": end_iso
                                    }
                                }
                            }
                        ],
                        "must_not": [
                            {"match": {"message": "Non-zero metrics in the last 30s"}}
                        ]
                    }
                }
            }

            response = self.client.post(f"/{self.log_index}/_search", query)
            hits = response.get("hits", {}).get("hits", [])
            
            # Return raw data for user to review
            results = []
            for hit in hits:
                results.append(hit.get("_source", {}))
                
            return {
                "host": host_name,
                "window": f"{window_minutes}m ({direction})",
                "start_time": start_iso,
                "end_time": end_iso,
                "log_count": len(results),
                "logs": results
            }
                
        except Exception as e:
            return {"error": f"Failed to query host logs: {str(e)}"}
