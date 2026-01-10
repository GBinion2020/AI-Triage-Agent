import requests
import os
from typing import Optional


class VirusTotalClient:
    """Client for querying VirusTotal API v3."""
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize VirusTotal client.
        
        Args:
            api_key: VT API key. If None, reads from environment variable VT_API_KEY
        """
        self.api_key = api_key or os.getenv('VT_API_KEY')
        if not self.api_key:
            raise ValueError("VirusTotal API key required. Set VT_API_KEY environment variable.")
        
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
    
    def lookup_ip(self, ip_address: str) -> dict:
        """
        Query VirusTotal for IP address reputation.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            Normalized reputation data
        """
        url = f"{self.base_url}/ip_addresses/{ip_address}"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            return self._normalize_response(data, "ip_address", ip_address)
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                return self._not_found_response("ip_address", ip_address)
            raise
        except Exception as e:
            return self._error_response("ip_address", ip_address, str(e))
    
    def lookup_domain(self, domain: str) -> dict:
        """
        Query VirusTotal for domain reputation.
        
        Args:
            domain: Domain name to check
            
        Returns:
            Normalized reputation data
        """
        url = f"{self.base_url}/domains/{domain}"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            return self._normalize_response(data, "domain", domain)
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                return self._not_found_response("domain", domain)
            raise
        except Exception as e:
            return self._error_response("domain", domain, str(e))
    
    def lookup_hash(self, file_hash: str) -> dict:
        """
        Query VirusTotal for file hash reputation.
        
        Args:
            file_hash: MD5, SHA1, or SHA256 hash
            
        Returns:
            Normalized reputation data
        """
        url = f"{self.base_url}/files/{file_hash}"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            return self._normalize_response(data, "hash", file_hash)
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                return self._not_found_response("hash", file_hash)
            raise
        except Exception as e:
            return self._error_response("hash", file_hash, str(e))
    
    def _normalize_response(self, raw_data: dict, indicator_type: str, indicator_value: str) -> dict:
        """
        Normalize VT API response to a standard format.
        
        Returns:
            {
                "indicator": str,
                "indicator_type": str,
                "reputation": "malicious|suspicious|clean|unknown",
                "detections": {
                    "malicious": int,
                    "suspicious": int,
                    "harmless": int,
                    "undetected": int,
                    "total": int
                },
                "tags": list[str],
                "last_analysis_date": str
            }
        """
        attributes = raw_data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected
        
        # Determine overall reputation
        if malicious > 0:
            reputation = "malicious"
        elif suspicious > 0:
            reputation = "suspicious"
        elif harmless > 0 or undetected > 0:
            reputation = "clean"
        else:
            reputation = "unknown"
        
        return {
            "indicator": indicator_value,
            "indicator_type": indicator_type,
            "reputation": reputation,
            "detections": {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "total": total
            },
            "tags": attributes.get("tags", []),
            "last_analysis_date": attributes.get("last_analysis_date", "unknown")
        }
    
    def _not_found_response(self, indicator_type: str, indicator_value: str) -> dict:
        """Return normalized response for IOC not found in VT database."""
        return {
            "indicator": indicator_value,
            "indicator_type": indicator_type,
            "reputation": "unknown",
            "detections": {
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "total": 0
            },
            "tags": [],
            "last_analysis_date": "never",
            "note": "Not found in VirusTotal database"
        }
    
    def _error_response(self, indicator_type: str, indicator_value: str, error: str) -> dict:
        """Return normalized error response."""
        return {
            "indicator": indicator_value,
            "indicator_type": indicator_type,
            "reputation": "error",
            "detections": {
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "total": 0
            },
            "tags": [],
            "last_analysis_date": "unknown",
            "error": error
        }
