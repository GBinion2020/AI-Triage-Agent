from typing import Dict, Any


class AlertContext:
    def __init__(self, alert: Dict[str, Any]):
        self.alert = alert
        self.source = alert.get("_source", {})

    def extract(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert.get("_id"),
            "timestamp": self.source.get("@timestamp"),

            "rule": self._rule(),
            "severity": self.source.get("kibana.alert.severity"),
            "risk_score": self.source.get("kibana.alert.risk_score"),
            "status": self.source.get("kibana.alert.workflow_status"),

            "host": self._host(),
            "user": self._user(),
            "process": self._process(),
            "powershell": self._powershell(),
            "event": self._event(),

            "message": self.source.get("message"),
        }

    # ---------------- Rule ----------------

    def _rule(self) -> Dict[str, Any]:
        return {
            "name": self.source.get("kibana.alert.rule.name"),
            "id": self.source.get("kibana.alert.rule.rule_id"),
            "description": self.source.get("kibana.alert.rule.description"),
            "author": self.source.get("kibana.alert.rule.author"),
            "references": self.source.get("kibana.alert.rule.references"),
            "tags": self.source.get("kibana.alert.rule.tags"),
        }

    # ---------------- Host ----------------

    def _host(self) -> Dict[str, Any]:
        host = self.source.get("host", {})
        return {
            "hostname": host.get("hostname"),
            "ip": host.get("ip"),
            "os": host.get("os", {}).get("name"),
            "architecture": host.get("architecture"),
        }

    # ---------------- User ----------------

    def _user(self) -> Dict[str, Any]:
        user = self.source.get("winlog", {}).get("user", {})
        return {
            "name": user.get("name"),
            "domain": user.get("domain"),
            "sid": user.get("identifier"),
        }

    # ---------------- Process ----------------

    def _process(self) -> Dict[str, Any]:
        winlog_proc = self.source.get("winlog", {}).get("process", {})
        return {
            "pid": winlog_proc.get("pid"),
            "event_code": self.source.get("event.code"),
            "provider": self.source.get("event.provider"),
        }

    # ---------------- PowerShell ----------------

    def _powershell(self) -> Dict[str, Any]:
        ps = self.source.get("powershell", {}).get("file", {})
        return {
            "script_block_id": ps.get("script_block_id"),
            "script_block_hash": ps.get("script_block_hash"),
            "script_block_text": ps.get("script_block_text"),
        }

    # ---------------- Event ----------------

    def _event(self) -> Dict[str, Any]:
        return {
            "action": self.source.get("event.action"),
            "category": self.source.get("event.category"),
            "type": self.source.get("event.type"),
            "dataset": self.source.get("event.dataset"),
            "module": self.source.get("event.module"),
        }
