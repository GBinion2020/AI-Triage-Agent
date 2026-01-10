import re


def tool_decision_prompt(alert_context: dict, mitre_context: list = None, history: list = None, turn: int = 1, max_turns: int = 3) -> str:
    """
    Generate prompt for LLM to decide if it needs to use external or internal investigation tools.
    """
    mitre_section = ""
    if mitre_context:
        mitre_section = "\n\n=== RELEVANT MITRE ATT&CK TECHNIQUES ===\n"
        for tech in mitre_context:
            mitre_section += f"• {tech['id']} - {tech['name']}\n"
    
    history_section = ""
    prohibited_section = ""
    if history:
        history_section = "\n\n=== INVESTIGATION HISTORY (Previous Turns) ===\n"
        for i, item in enumerate(history):
            history_section += f"[{i+1}] {item['tool']} -> {item['summary']}\n"
            
        prohibited_section = "\n\n=== PROHIBITED QUERIES (Choose DIFFERENT parameters) ===\n"
        for item in history:
            if item.get('query_sig') and item['query_sig'] != "RESTRICTION_TRIGGERED":
                prohibited_section += f"• {item['query_sig']}\n"

    remaining = max_turns - turn + 1
    
    return f"""You are a SOC Tier 2 security analyst analyzing the following alert:{mitre_section}{history_section}{prohibited_section}

===  ALERT CONTEXT ===
{alert_context}

=== INVESTIGATION BUDGET ===
Turn: {turn} of {max_turns}
Remaining Tool Calls: {remaining}

=== AVAILABLE TOOLS ===
1. query_virustotal: Check indicator reputation (OPTIONAL).
2. query_siem_host_logs: Query the SIEM for host logs (MANDATORY at least once).

=== YOUR TASK ===
Based on the history, do you need more context or are you ready to classify?

IMPORTANT: 
- MANDATORY: You MUST use query_siem_host_logs at least once before you can CLASSIFY.
- PROHIBITION: You are FORBIDDEN from repeating any query listed in the 'PROHIBITED QUERIES' section above.
- STRICT FORMATTING: The IOC_VALUE field must contain ONLY the raw indicator. DO NOT add thoughts into parameter fields.
- If you have already used the SIEM and have enough info, decide to CLASSIFY.

Response Format:
THOUGHT: <explain your reasoning for the next step, referencing the history if applicable>
DECISION: <TOOL or CLASSIFY>

If DECISION is TOOL:
TOOL_NAME: query_virustotal
IOC_TYPE: <IP | DOMAIN | HASH>
IOC_VALUE: <value>

If DECISION is TOOL and name is SIEM:
TOOL_NAME: query_siem_host_logs
WINDOW_MINUTES: <1-60>
DIRECTION: <BEFORE | AFTER | CENTERED>
"""


def parse_tool_decision(response: str) -> dict:
    """
    Parse LLM's multi-turn tool decision response.
    """
    decision = {
        "use_tool": False,
        "tool_name": None,
        "thought": "",
        "params": {}
    }
    
    # Extract THOUGHT
    thought_match = re.search(r"THOUGHT:\s*(.*?)(?=\s*\w+:\s*|$)", response, re.IGNORECASE | re.DOTALL)
    if thought_match:
        decision["thought"] = thought_match.group(1).strip()
    
    # Extract DECISION
    decision_match = re.search(r"DECISION:\s*(\w+)", response, re.IGNORECASE)
    if decision_match and decision_match.group(1).upper() == "TOOL":
        decision["use_tool"] = True
    
    # Extract TOOL_NAME
    name_match = re.search(r"TOOL_NAME:\s*(\w+)", response, re.IGNORECASE)
    if name_match:
        decision["tool_name"] = name_match.group(1).lower()
    
        if decision["tool_name"] == "query_virustotal":
            type_match = re.search(r"IOC_TYPE:\s*(\w+)", response, re.IGNORECASE)
            value_match = re.search(r"IOC_VALUE:\s*(.*?)(?=\s*\w+:\s*|$)", response, re.IGNORECASE | re.DOTALL)
            if type_match:
                decision["params"]["ioc_type"] = type_match.group(1).upper()
            if value_match:
                # SANITIZE: Take only the first "word" to remove any trailing LLM thoughts/punctuation
                raw_value = value_match.group(1).strip().strip('"').strip("'")
                sanitized_value = raw_value.split()[0] if raw_value else ""
                decision["params"]["ioc_value"] = sanitized_value
        
        elif decision["tool_name"] == "query_siem_host_logs":
            window_match = re.search(r"WINDOW_MINUTES:\s*(\d+)", response, re.IGNORECASE)
            direction_match = re.search(r"DIRECTION:\s*(\w+)", response, re.IGNORECASE)
            if window_match:
                decision["params"]["window_minutes"] = int(window_match.group(1))
            if direction_match:
                decision["params"]["direction"] = direction_match.group(1).upper()
    
    return decision


def enrichment_prompt(alert_context: dict, mitre_context: list, history: list) -> str:
    """
    Generate final classification prompt with full investigation history.
    """
    from llm.prompts import triage_prompt
    import json
    
    enrichment_section = "\n\n=== INVESTIGATION JOURNAL ==="
    
    for item in history:
        enrichment_section += f"\n\n--- Turn {item['turn']}: {item['tool']} ---"
        enrichment_section += f"\nResult Summary: {item['summary']}"
        
        # Add raw data preview for SIEM logs or VT detections
        if 'result' in item and 'logs' in item['result']:
            enrichment_section += "\nSample Raw Logs (JSON):"
            for log in item['result']['logs'][:5]:
                enrichment_section += f"\n{json.dumps(log, indent=2)}"
        elif 'result' in item and 'reputation' in item['result']:
            res = item['result']
            enrichment_section += f"\nFull VT Reputation: {res['reputation'].upper()} ({res['detections']['malicious']}/{res['detections']['total']})"
            
    # Use existing triage prompt and inject journal
    base_prompt = triage_prompt(alert_context, mitre_context)
    
    return base_prompt.replace(
        "CLASSIFICATION:",
        f"{enrichment_section}\n\n"
        "=== FINAL INSTRUCTION ===\n"
        "The investigation is complete. Analyze the entire history above. "
        "Explicitly state in your REASONING how each turn of the investigation influenced your final verdict.\n\n"
        "CLASSIFICATION:"
    )
