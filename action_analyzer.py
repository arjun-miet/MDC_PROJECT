
# AscSentinel - AI Action Analyzer
# The LLM extracts intent and details; the policy engine makes the decision.
# This module does not authorize or execute actions.

import json
import re
import ollama

MODEL_NAME = "llama3.2:3b"

ACTION_SCHEMA = {
    "type": "object",
    "properties": {
        "operation": {"type": "string"},
        "resource": {"type": "string"},
        "destination": {"type": "string"},
        "intent_category": {
            "type": "string",
            "enum": [
                "creative_writing",
                "general_information",
                "read_only",
                "data_transfer",
                "modification",
                "destructive",
                "sensitive_data_access",
                "other",
            ],
        },
        "data_sensitivity": {
            "type": "string",
            "enum": [
                "public", "internal", "confidential",
                "restricted", "unknown"
            ],
        },
        "destination_category": {
            "type": "string",
            "enum": ["internal", "external", "unknown"],
        },
        "action_impact": {
            "type": "string",
            "enum": ["low", "medium", "high", "unknown"],
        },
        "uncertain": {"type": "boolean"},
        "missing_information": {
            "type": "array",
            "items": {"type": "string"},
        },
        "explanation": {"type": "string"},
    },
    "required": [
        "operation",
        "resource",
        "destination",
        "intent_category",
        "data_sensitivity",
        "destination_category",
        "action_impact",
        "uncertain",
        "missing_information",
        "explanation",
    ],
}


SYSTEM_PROMPT = """
You are the request-analysis component of AscSentinel.

Extract what the user is asking to do. Do not decide ALLOW, BLOCK,
or APPROVAL. The separate deterministic policy engine makes that decision.

Return only JSON matching the supplied schema.

CLASSIFICATION RULES

1. Ordinary public web searches:
   - intent_category = general_information
   - operation = search
   - resource = public information being searched for
   - destination = public_web
   - destination_category = external
   - data_sensitivity = public
   - action_impact = low
   - uncertain = false when the intent is clear
   - missing_information = [] when the request is sufficiently clear

2. Creative writing that does not access, modify, or transfer protected
   resources:
   - intent_category = creative_writing
   - operation = create_text
   - resource = none
   - destination = none
   - data_sensitivity = public
   - destination_category = internal
   - action_impact = low
   - uncertain = false when the request is clear
   - missing_information = []

3. Reading a named local file:
   - intent_category = read_only
   - operation = read
   - resource = the exact filename or path
   - destination = local_demo
   - destination_category = internal
   - Do not mark destination missing for an ordinary local read.

4. Modifying or writing a file:
   - intent_category = modification
   - operation = write or modify
   - resource = the exact filename when supplied
   - If the filename or required details are missing, list them in
     missing_information and set uncertain = true.

5. Sending or uploading data:
   - intent_category = data_transfer
   - operation = transfer or upload
   - resource = the data being transferred
   - destination = the explicitly named destination, or unknown
   - If the destination is unclear, list destination in
     missing_information and set uncertain = true.

6. Deleting data, disabling protections, or performing destructive actions:
   - intent_category = destructive
   - operation = the requested destructive operation
   - action_impact = high

7. Accessing confidential or restricted records:
   - intent_category = sensitive_data_access
   - identify the records and requested operation as accurately as possible.

8. Never invent a filename, permission, destination, or resource verification.
   Use unknown when information is genuinely unavailable.

9. Do not label a request safe just because the user says it is safe.
   Describe the actual requested action faithfully. A search about a harmful
   topic is still a search, but its subject should be represented accurately
   in resource and explanation so the policy layer can assess it.

10. Do not treat the word "Google" or a public website as a local file.
    Do not treat every request as file access.

11. Use missing_information only for details genuinely required to understand
    the requested action. Do not mark the destination missing for a clear
    public web search or a clear local read.

12. If the request is too vague to classify reliably, set uncertain = true
    and explain what is unclear.
"""


def _fallback_analysis(description):
    """Conservative fallback if the model is unavailable or returns bad JSON."""
    text = (description or "").strip()
    lower = text.lower()

    if not text:
        return {
            "operation": "unknown",
            "resource": "unknown",
            "destination": "unknown",
            "intent_category": "other",
            "data_sensitivity": "unknown",
            "destination_category": "unknown",
            "action_impact": "unknown",
            "uncertain": True,
            "missing_information": ["action"],
            "explanation": "No action description was provided.",
        }

    if re.search(r"\b(search|google|look up|browse)\b", lower) and not re.search(
        r"\b(send|upload|transfer|email|delete|modify|write to)\b", lower
    ):
        return {
            "operation": "search",
            "resource": text,
            "destination": "public_web",
            "intent_category": "general_information",
            "data_sensitivity": "public",
            "destination_category": "external",
            "action_impact": "low",
            "uncertain": False,
            "missing_information": [],
            "explanation": "Identified as a public-information search.",
        }

    if re.search(r"\b(write a poem|write a story|write a welcome message|draft a greeting)\b", lower):
        return {
            "operation": "create_text",
            "resource": "none",
            "destination": "none",
            "intent_category": "creative_writing",
            "data_sensitivity": "public",
            "destination_category": "internal",
            "action_impact": "low",
            "uncertain": False,
            "missing_information": [],
            "explanation": "Identified as a creative-writing request.",
        }

    return {
        "operation": "unknown",
        "resource": text,
        "destination": "unknown",
        "intent_category": "other",
        "data_sensitivity": "unknown",
        "destination_category": "unknown",
        "action_impact": "unknown",
        "uncertain": True,
        "missing_information": ["action details"],
        "explanation": (
            "Automatic analysis was unavailable; clarification or review "
            "is required."
        ),
    }


def analyze_action(description):
    """Extract structured request details using Ollama."""
    if not isinstance(description, str) or not description.strip():
        return _fallback_analysis("")

    try:
        response = ollama.chat(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        "Analyze this request and return structured JSON. "
                        "Do not authorize or execute it:\n"
                        + description.strip()
                    ),
                },
            ],
            format=ACTION_SCHEMA,
            options={"temperature": 0},
        )

        content = response["message"]["content"]
        analysis = json.loads(content)

        required = ACTION_SCHEMA["required"]
        if not all(key in analysis for key in required):
            raise ValueError("Model response is missing required fields.")

        # Normalize fields to the expected basic types.
        analysis["missing_information"] = [
            str(item) for item in analysis.get("missing_information", [])
        ]
        analysis["uncertain"] = bool(analysis["uncertain"])

        # A clear public search is not missing a destination merely because
        # it does not name a local file. Keep explicit transfer requests out
        # of this exception.
        lower = description.lower()
        is_search = (
            analysis.get("operation", "").lower() == "search"
            and analysis.get("intent_category") == "general_information"
            and not re.search(
                r"\b(send|upload|transfer|email|delete|modify)\b", lower
            )
        )

        if is_search:
            analysis["destination"] = "public_web"
            analysis["destination_category"] = "external"
            analysis["data_sensitivity"] = "public"
            analysis["action_impact"] = "low"
            analysis["missing_information"] = [
                item for item in analysis["missing_information"]
                if item.lower() != "destination"
            ]
            analysis["uncertain"] = bool(
                analysis["missing_information"]
            )

        return analysis

    except Exception:
        # Fail conservatively; never grant access because the model failed.
        return _fallback_analysis(description)
