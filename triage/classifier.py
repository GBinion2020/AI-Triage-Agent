import json
from llm.client import LLMClient
from llm.prompts import triage_prompt
from triage.schemas import validate_triage_output, default_response


class AlertClassifier:
    def __init__(self, model: str = "llama3.1:8b"):
        self.llm = LLMClient(model=model)

    def classify(self, alert_context: dict) -> dict:
        prompt = triage_prompt(alert_context)

        try:
            raw_response = self.llm.generate(prompt)
            parsed = json.loads(raw_response)
        except json.JSONDecodeError:
            return default_response("LLM returned non-JSON output")
        except Exception as e:
            return default_response(str(e))

        return validate_triage_output(parsed)
