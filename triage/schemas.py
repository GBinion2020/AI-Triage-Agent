TRIAGE_SCHEMA = {
    "classification": {"not malicious", "suspicious", "malicious", "undecided"},
    "recommended_action": {"ignore", "investigate", "contain", "escalate"}
}


def validate_triage_output(data: dict) -> dict:
    """
    Ensures the LLM output conforms to expectations.
    Applies safe defaults if validation fails.
    """

    if not isinstance(data, dict):
        return default_response("Invalid response type")

    if data.get("classification") not in TRIAGE_SCHEMA["classification"]:
        return default_response("Invalid classification")

    if data.get("recommended_action") not in TRIAGE_SCHEMA["recommended_action"]:
        return default_response("Invalid recommended_action")

    if not isinstance(data.get("confidence"), int):
        return default_response("Invalid confidence score")

    return data


def default_response(reason: str) -> dict:
    return {
        "classification": "suspicious",
        "confidence": 0,
        "reasoning": reason,
        "recommended_action": "investigate",
        "mitre_techniques": []
    }
