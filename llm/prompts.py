def triage_prompt(alert_context: dict, mitre_context: list = None) -> str:
    """Generate triage prompt with optional MITRE ATT&CK context from RAG."""
    
    # Build MITRE context section if available
    mitre_section = ""
    if mitre_context:
        mitre_section = "\n\n=== RELEVANT MITRE ATT&CK TECHNIQUES (from knowledge base) ===\n"
        for tech in mitre_context:
            mitre_section += f"\n• {tech['id']} - {tech['name']}\n"
            mitre_section += f"  {tech['description'][:200]}...\n"
    
    return f"""You are a SOC Tier 2 security analyst. Analyze the security alert below and fill in each field with your assessment.{mitre_section}

CLASSIFICATION: <Not Malicious, Undecided, Suspicious, or Malicious based on your investigation of the alert>
CONFIDENCE: <number from 0-100 based on your investigation of the alert>
REASONING: <2-3 sentence technical explanation. If you used a tool (VirusTotal or SIEM), you MUST explicitly state how those results influenced your decision.>
RECOMMENDED_ACTION: <ignore, investigate, contain, or escalate>
MITRE_TECHNIQUES: <comma-separated technique IDs like T1059, T1086, or "none">

Important: Your confidence rate is based on your investigation decision:
- 80-100: MALICIOUS (Confirmed threat or highly suspicious activity with no legitimate explanation)
- 60-80: SUSPICIOUS (Anomalous activity that warrants investigation but lacks definitive proof of malice)
- 30-60: UNDECIDED (Insufficient data to lean either way, even after using available tools)
- 0-30: NOT MALICIOUS (Identified as legitimate business activity or false positive)

Note: You are provided with ENRICHMENT DATA if you previously requested it. You must analyze this data. Only use UNDECIDED if the enrichment data provided is still contradictory or completely missing key info. Prefer SUSPICIOUS if the activity is anomalous but unconfirmed.
Alert Context:
{alert_context}
"""
