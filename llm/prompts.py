def triage_prompt(alert_context: dict) -> str:
    return f"""
You are a SOC Tier 2 security analyst.

Analyze the following normalized security alert and return a response in JSON ONLY.
Do not include markdown, explanations, or extra text.

Required JSON schema:
{{
  "classification": "benign | suspicious | malicious",
  "confidence": 0-100,
  "reasoning": "concise technical explanation",
  "recommended_action": "ignore | investigate | contain | escalate",
  "mitre_techniques": ["TXXXX"]
}}

Alert Context:
{alert_context}
"""
