import re
import json
from llm.client import LLMClient
from llm.prompts import triage_prompt
from triage.schemas import validate_triage_output, default_response
from rag.vectordb import MITREVectorDB


class AlertClassifier:
    def __init__(self, model: str = "llama3.1:8b"):
        self.llm = LLMClient(model=model)
        
        # Initialize RAG vector database
        try:
            self.vector_db = MITREVectorDB()
            self.rag_enabled = True
            print("[OK] RAG enabled: MITRE knowledge base loaded")
        except Exception as e:
            print(f"! RAG disabled: {e}")
            self.rag_enabled = False

    def classify(self, alert_context: dict) -> dict:
        """
        Standard classification without tool calling.
        For backwards compatibility.
        """
        # Get MITRE context via RAG (if enabled)
        mitre_context = []
        if self.rag_enabled:
            mitre_context = self._retrieve_mitre_context(alert_context)
        
        # Generate prompt with RAG context
        prompt = triage_prompt(alert_context, mitre_context)

        try:
            raw_response = self.llm.generate(prompt)
            parsed = self._parse_template_response(raw_response)
        except Exception as e:
            return default_response(f"Parsing error: {str(e)}")

        return validate_triage_output(parsed)
    
    def classify_with_tools(self, alert_context: dict) -> dict:
        """
        Iterative investigation loop (up to 3 turns) with memory.
        """
        # 1. Get MITRE context from RAG
        mitre_context = []
        if self.rag_enabled:
            mitre_context = self._retrieve_mitre_context(alert_context)
        
        # 2. Initialize Investigation Journal
        investigation_history = []
        max_turns = 5
        turn = 1
        
        while turn <= max_turns:
            print(f"\n[TURN {turn}/{max_turns}] Investigating...")
            
            # 3. Ask LLM for next step based on current history
            tool_decision = self._get_tool_decision(alert_context, mitre_context, investigation_history, turn, max_turns)
            
            if not tool_decision['use_tool']:
                # Check if SIEM has been used (at least once without error)
                used_tools = set(h['tool'] for h in investigation_history if not h.get('error'))
                mandatory_tools = {"query_siem_host_logs"}
                missing_tools = mandatory_tools - used_tools
                
                if missing_tools:
                    print(f"   [!] Forced investigation: LLM tried to classify without using {list(missing_tools)}")
                    investigation_history.append({
                        "turn": turn,
                        "tool": "SYSTEM",
                        "query_sig": "RESTRICTION_TRIGGERED",
                        "summary": f"REJECTED: You MUST use {', '.join(missing_tools)} at least once before you are allowed to classify.",
                        "error": "Mandatory tools missing"
                    })
                    turn += 1
                    continue

                print(f"[IDLE] LLM decision: Ready for final classification.")
                break
                
            tool_name = tool_decision['tool_name']
            params = tool_decision['params']
            
            # Check for duplicate queries in history (normalize dicts for comparison)
            query_sig = f"{tool_name}({json.dumps(params, sort_keys=True)})"
            if any(h['query_sig'] == query_sig for h in investigation_history):
                print(f"   [!] Duplicate query detected: {query_sig}")
                investigation_history.append({
                    "turn": turn,
                    "tool": tool_name,
                    "query_sig": query_sig,
                    "summary": "DUPLICATE QUERY BLOCKED. You already performed this exact query. Please try different parameters.",
                    "error": "Duplicate query"
                })
                turn += 1
                continue

            print(f"[TOOL] LLM requested: {tool_name}")
            print(f"   Thought: {tool_decision.get('thought', 'No thought provided')}")
            
            # 4. Execute tool
            tool_result = None
            if tool_name == "query_virustotal":
                tool_result = self._execute_virustotal(params)
            elif tool_name == "query_siem_host_logs":
                tool_result = self._execute_siem_query(alert_context, params)
            else:
                tool_result = {"error": f"Unknown tool: {tool_name}"}

            # 5. Summarize and add to history
            summary = self._summarize_tool_result(tool_name, tool_result)
            investigation_history.append({
                "turn": turn,
                "tool": tool_name,
                "query_sig": query_sig,
                "summary": summary,
                "result": tool_result
            })
            
            print(f"   [RESULT] {summary[:100]}...")
            turn += 1

        # 6. Final classification with all gathered evidence
        return self._classify_with_enrichment(alert_context, mitre_context, investigation_history)
    
    def _get_tool_decision(self, alert_context: dict, mitre_context: list, history: list, turn: int, max_turns: int) -> dict:
        """Ask LLM if it wants to use a tool, providing history and budget."""
        from llm.tool_prompts import tool_decision_prompt, parse_tool_decision
        
        prompt = tool_decision_prompt(alert_context, mitre_context, history, turn, max_turns)
        
        try:
            raw_response = self.llm.generate(prompt)
            decision = parse_tool_decision(raw_response)
            return decision
        except Exception as e:
            print(f"Error getting tool decision: {e}")
            return {"use_tool": False, "reasoning": f"Error: {e}"}
    
    def _summarize_tool_result(self, tool_name: str, result: dict) -> str:
        """Create a concise summary of tool output for the journal."""
        if result.get('error'):
            return f"Error: {result['error']}"
            
        if tool_name == "query_virustotal":
            return f"VirusTotal reported indicator as {result['reputation'].upper()} with {result['detections']['malicious']}/{result['detections']['total']} detections."
            
        if tool_name == "query_siem_host_logs":
            count = result.get('log_count', 0)
            if count == 0:
                return "SIEM query returned 0 logs in the specified timeframe. No matching host activity found."
            
            # Grab actions and unique processes (cast to str to avoid unhashable type error)
            actions = list(set(str(log.get('event', {}).get('action') or log.get('action') or "") for log in result['logs'][:10] if log))
            processes = list(set(str(log.get('process', {}).get('name') or log.get('process') or "") for log in result['logs'][:10] if log))
            
            # Clean up empty strings
            actions = [a for a in actions if a]
            processes = [p for p in processes if p]
            
            summary = f"SIEM found {count} logs. Found actions: {', '.join(actions)[:100]}. "
            summary += f"Active processes: {', '.join(processes)[:100]}."
            return summary
            
        return "Tool executed successfully but no summary logic implemented."
    
    
    def _execute_virustotal(self, params: dict) -> dict:
        """Execute VirusTotal lookup based on IOC type."""
        from enrichment.virustotal import VirusTotalClient
        
        try:
            vt = VirusTotalClient()
            ioc_type = params.get('ioc_type')
            ioc_value = params.get('ioc_value')
            
            if ioc_type == "IP":
                return vt.lookup_ip(ioc_value)
            elif ioc_type == "DOMAIN":
                return vt.lookup_domain(ioc_value)
            elif ioc_type == "HASH":
                return vt.lookup_hash(ioc_value)
            else:
                return {"error": f"Unknown IOC type: {ioc_type}"}
        except Exception as e:
            return {"error": f"VirusTotal query failed: {str(e)}"}

    def _execute_siem_query(self, alert_context: dict, params: dict) -> dict:
        """Execute SIEM host log query."""
        from elastic.investigation import HostLogSearcher
        
        try:
            searcher = HostLogSearcher()
            host_name = alert_context.get('host', {}).get('hostname')
            timestamp = alert_context.get('timestamp')
            
            if not host_name or not timestamp:
                return {"error": "Missing host name or timestamp in alert context"}
                
            return searcher.search_host_logs(
                host_name=host_name,
                alert_timestamp=timestamp,
                window_minutes=params.get('window_minutes', 15),
                direction=params.get('direction', 'CENTERED')
            )
        except Exception as e:
            return {"error": f"SIEM query failed: {str(e)}"}
    
    def _classify_with_enrichment(self, alert_context: dict, mitre_context: list, history: list = None) -> dict:
        """Final classification incorporating the entire investigation journal."""
        from llm.tool_prompts import enrichment_prompt
        
        if history:
            prompt = enrichment_prompt(alert_context, mitre_context, history)
        else:
            prompt = triage_prompt(alert_context, mitre_context)
        
        # DEBUG: Print first 500 chars of final prompt to see enrichment injection
        # print(f"\n--- DEBUG: FINAL PROMPT (TOP 500) ---\n{prompt[:500]}...\n")
        # print(f"--- DEBUG: ENRICHMENT SECTION ---\n{prompt[prompt.find('=== ENRICHMENT DATA ==='):][:1000]}\n")
        
        try:
            raw_response = self.llm.generate(prompt)
            parsed = self._parse_template_response(raw_response)
            
            # Add investigation journal to result for transparency
            if history:
                parsed['investigation_history'] = history
            
            return validate_triage_output(parsed)
        except Exception as e:
            return default_response(f"Classification error: {str(e)}")
    
    def _retrieve_mitre_context(self, alert_context: dict) -> list:
        """Query vector DB for relevant MITRE techniques."""
        # Build search query from alert context
        query_parts = []
        
        if alert_context.get('rule', {}).get('name'):
            query_parts.append(alert_context['rule']['name'])
        
        if alert_context.get('rule', {}).get('description'):
            query_parts.append(alert_context['rule']['description'])
        
        if alert_context.get('process'):
            process_info = alert_context['process']
            if process_info.get('provider'):
                query_parts.append(process_info['provider'])
        
        query_text = " ".join(query_parts)
        
        # Query vector database
        try:
            techniques = self.vector_db.query_attack_techniques(query_text, n_results=3)
            return techniques
        except Exception as e:
            print(f"RAG query failed: {e}")
            return []

    def _parse_template_response(self, response: str) -> dict:
        """Extract values from the LLM's template response."""
        
        # Clean markdown headers (hashes) which some models like Qwen use
        response = re.sub(r'(?m)^#+\s*', '', response)
        
        # 1. Extract Classification (Allow for markdown symbols like # or * at the start)
        classification = self._extract_field(response, r"(?:^|\n)[#*]*\s*CLASSIFICATION\s*[*#]*:\s*(.*?)(?=\s*[*#]*[A-Z_]{4,}[*#]*:\s*|$)", 
                                           ["not malicious", "undecided", "suspicious", "malicious"])
        
        # 2. Extract Confidence
        confidence = self._extract_confidence(response)
        
        # 3. Extract Reasoning (multi-line, allow for markdown headers)
        reasoning = self._extract_field(response, r"(?:^|\n)[#*]*\s*REASONING\s*[*#]*:\s*(.*?)(?=\s*[*#]*[A-Z_]{4,}[*#]*:\s*|$)", is_multiline=True)
        
        # 4. Extract Action
        action = self._extract_field(response, r"(?:^|\n)[#*]*\s*RECOMMENDED_ACTION\s*[*#]*:\s*(.*?)(?=\s*[*#]*[A-Z_]{4,}[*#]*:\s*|$)")
        action = self._normalize_action(action)
        
        # 5. Extract Techniques
        techniques = self._extract_techniques(response)

        return {
            "classification": classification,
            "confidence": confidence,
            "reasoning": reasoning,
            "recommended_action": action,
            "mitre_techniques": techniques
        }

    def _normalize_action(self, action: str) -> str:
        """Normalize recommended action to schema values."""
        valid_actions = ["ignore", "investigate", "contain", "escalate"]
        action_lower = action.lower()
        for valid in valid_actions:
            if valid in action_lower:
                return valid
        return "investigate"

    def _extract_field(self, text: str, pattern: str, valid_options: list = None, is_multiline: bool = False) -> str:
        """Extract a single field value from the response using regex."""
        flags = re.IGNORECASE
        if is_multiline:
            flags |= re.DOTALL
            
        match = re.search(pattern, text, flags)
        if not match:
            return "unknown"
        
        value = match.group(1).strip()
        
        # Remove markdown bold/italic tags, headers, and common delimiters
        value = re.sub(r'[*_`#]', '', value)
        
        if not is_multiline:
            value = value.lower()
            value = re.sub(r'[<>\'"[\]:]', '', value) # Also remove colons that might leak
        
        # If valid options provided, check for BEST match
        if valid_options:
            value_lower = value.lower()
            # Order matters: check longest/most specific first (e.g., 'not malicious' before 'malicious')
            sorted_options = sorted(valid_options, key=len, reverse=True)
            for option in sorted_options:
                if option in value_lower:
                    return option
            return "unknown"
        
        return value

    def _extract_confidence(self, text: str) -> int:
        """Extract confidence score as an integer."""
        # Clean text first to remove markdown noise
        clean_text = re.sub(r'[*_`#]', '', text)
        
        match = re.search(r"(?:^|\n)[#*]*\s*CONFIDENCE\s*[*#]*:\s*(\d+)", clean_text, re.IGNORECASE)
        if not match:
            return 50  # Default
        
        try:
            return int(match.group(1))
        except:
            return 50

    def _extract_techniques(self, text: str) -> list:
        """Extract MITRE technique IDs."""
        # Use _extract_field logic for consistency
        raw_tech = self._extract_field(text, r"(?:^|\n)[#*]*\s*MITRE_TECHNIQUES\s*[*#]*:\s*(.*?)(?=\s*[*#]*[A-Z_]{4,}[*#]*:\s*|$)", is_multiline=True)
        
        if not raw_tech or "none" in raw_tech.lower() or raw_tech == "unknown":
            return []
        
        # Extract T#### patterns
        technique_ids = re.findall(r'T\d{4}(?:\.\d{3})?', raw_tech, re.IGNORECASE)
        return list(set(t.upper() for t in technique_ids))
