import re
from typing import Dict, List


class IOCExtractor:
    """
    Optional utility for extracting IOCs from alert context.
    Used for statistics/metadata only. Not required for validation.
    """
    
    @staticmethod
    def extract_ips(alert_context: dict) -> List[str]:
        """Extract IP addresses from alert context."""
        import json
        alert_str = json.dumps(alert_context, default=str)
        
        # IPv4 pattern
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, alert_str)
        
        # Filter out invalid IPs (basic validation)
        valid_ips = []
        for ip in ips:
            octets = ip.split('.')
            if all(0 <= int(octet) <= 255 for octet in octets):
                valid_ips.append(ip)
        
        return list(set(valid_ips))  # Deduplicate
    
    @staticmethod
    def extract_domains(alert_context: dict) -> List[str]:
        """Extract domain names from alert context."""
        import json
        alert_str = json.dumps(alert_context, default=str)
        
        # Basic domain pattern
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        domains = re.findall(domain_pattern, alert_str)
        
        return list(set(domains))  # Deduplicate
    
    @staticmethod
    def extract_hashes(alert_context: dict) -> List[str]:
        """Extract file hashes (MD5, SHA1, SHA256) from alert context."""
        import json
        alert_str = json.dumps(alert_context, default=str)
        
        hashes = []
        
        # MD5 (32 hex chars)
        md5_pattern = r'\b[a-fA-F0-9]{32}\b'
        hashes.extend(re.findall(md5_pattern, alert_str))
        
        # SHA1 (40 hex chars)
        sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
        hashes.extend(re.findall(sha1_pattern, alert_str))
        
        # SHA256 (64 hex chars)
        sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
        hashes.extend(re.findall(sha256_pattern, alert_str))
        
        return list(set(hashes))  # Deduplicate
    
    @staticmethod
    def extract_all(alert_context: dict) -> Dict[str, List[str]]:
        """Extract all IOC types from alert context."""
        return {
            "ips": IOCExtractor.extract_ips(alert_context),
            "domains": IOCExtractor.extract_domains(alert_context),
            "hashes": IOCExtractor.extract_hashes(alert_context)
        }
