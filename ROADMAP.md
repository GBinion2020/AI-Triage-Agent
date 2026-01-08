# Project Roadmap

This document outlines the development direction for the SOC AI Triage Agent. The current release (v1) focuses on initial alert classification using normalized context data. Future versions will aim to enhance the agent's autonomy and depth of analysis.

## Current State: Version 1.0 (MVP)

*   **Core Functionality:**
    *   Ingests alerts from Elastic SIEM.
    *   Normalizes alert data into a consistent `AlertContext`.
    *   Uses a local LLM (`llama3.1:8b`) to classify alerts as Benign, Suspicious, or Malicious.
    *   Provides recommended actions and mapping to MITRE ATT&CK techniques.

## Future Scope & Direction

### Phase 2: Autonomous Investigation (Active Querying)
The next major iteration will transform the agent from a passive analyzer to an active investigator.
*   **Elasticsearch Querying:** Instead of relying solely on the initial alert data, the agent will be capable of generating and executing follow-up KQL queries to Elastic.
    *   *Example:* Identifying if a suspicious IP has been seen in other logs (Firewall, DNS) over the past 30 days.
    *   *Example:* Checking for other process executions by the same user around the time of the alert.
*   **Context-Driven Analysis:** The agent will use the results of these queries to build a deeper, multi-faceted context before making a final decision.

### Phase 3: External Enrichment & Threat Intelligence
To further validate findings, the agent will integrate with third-party security APIs.
*   **VirusTotal Integration:** Automatically query file hashes, domains, and IP addresses against VirusTotal to gather reputation data.
*   **Threat Intel Feeds:** Cross-reference observables with other configured threat intelligence sources.

### Phase 4: Active Response (Planned)
*   **Automated Containment:** Capability to execute containment actions (e.g., isolating a host) if the confidence score meets a high threshold (95%+).
