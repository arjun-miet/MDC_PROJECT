"""Deterministic policy evaluation for the AscSentinel simulation.

Hard authorization rules are evaluated before risk thresholds. Risk scores are
explainable signals; they never override a denied permission or prohibited
destination. No action is executed by this module.
"""

SENSITIVITY_RISK = {
    "public": 0,
    "internal": 10,
    "confidential": 20,
    "restricted": 30,
    "unknown": 25,
}
DESTINATION_RISK = {
    "trusted": 0,
    "known_external": 20,
    "unknown": 25,
    "prohibited": 40,
}
IMPACT_RISK = {"low": 0, "medium": 10, "high": 20, "unknown": 15}

# Decision thresholds, applied after hard policy checks.
ALLOW_MAX_RISK = 29
APPROVAL_MAX_RISK = 59

def _normalize(value):
    return str(value or "").strip().lower()

def calculate_risk(analysis):
    """Return a deterministic integer risk score from 0 to 100.

    Base score = sensitivity + destination + impact. Add 25 once if the
    request describes a destructive operation, 20 for confidential/restricted
    data going to an external/unknown/prohibited destination, 10 for model
    uncertainty, 10 when required information is missing, and 20 for an
    explicitly destructive intent. The final score is capped at 100.
    """
    a = analysis or {}
    sensitivity = _normalize(a.get("resource_classification") or a.get("data_sensitivity") or "unknown")
    destination = _normalize(a.get("destination_risk") or a.get("destination_category") or "unknown")
    impact = _normalize(a.get("action_impact", "unknown"))
    score = SENSITIVITY_RISK.get(sensitivity, SENSITIVITY_RISK["unknown"])
    score += DESTINATION_RISK.get(destination, DESTINATION_RISK["unknown"])
    score += IMPACT_RISK.get(impact, IMPACT_RISK["unknown"])

    description = _normalize(a.get("action_description", ""))
    operation = _normalize(a.get("operation", ""))
    destructive_terms = ("delete", "remove", "erase", "destroy", "drop database", "wipe", "purge", "overwrite")
    destructive = any(term in description for term in destructive_terms) or any(term in operation for term in destructive_terms)
    if destructive:
        score += 25

    intent = _normalize(a.get("intent_category", "other"))
    if destination in {"known_external", "unknown", "prohibited"} and sensitivity in {"confidential", "restricted"}:
        score += 20
    if bool(a.get("uncertain", False)):
        score += 10
    if a.get("missing_information"):
        score += 10
    if intent == "destructive":
        score += 20
    return min(100, max(0, int(score)))

def _result(decision, score, reasons):
    return {"decision": decision, "risk_score": score, "reasons": reasons, "executed": False, "simulation": True}

def _is_destructive_request(analysis):
    """Conservatively identify destructive operations from structured fields and text."""
    a = analysis or {}
    operation = _normalize(a.get("operation", "")).replace("-", "_")
    intent = _normalize(a.get("intent_category", ""))
    description = _normalize(a.get("action_description", ""))
    resource = _normalize(a.get("resource", ""))

    destructive_operations = {
        "delete", "remove", "erase", "destroy", "drop", "drop_database",
        "wipe", "purge", "truncate", "format", "disable_security",
    }
    if operation in destructive_operations or intent == "destructive":
        return True

    phrases = (
        "delete all", "permanently delete", "delete permanently",
        "delete all records", "drop database", "wipe database",
        "erase all", "destroy all", "truncate table",
        "remove all records", "purge all",
        "disable all security", "turn off security protections",
    )
    combined = f"{description} {resource}"
    return any(phrase in combined for phrase in phrases)


def evaluate_action(policy_input):
    """Return ALLOW, BLOCK, or APPROVAL from trusted context and risk.

    BLOCK: explicit authorization denial, prohibited policy/destination.
    APPROVAL: unverified resource, unknown operation, incomplete request, or
    score >= 30 where human review is required.
    ALLOW: verified resource, granted permission, known operation, complete
    request, and score < 30. Creative writing that accesses no resource is a
    harmless simulation action and is allowed without resource authorization.
    """
    a = policy_input or {}
    intent = _normalize(a.get("intent_category", "other"))
    if intent == "creative_writing":
        return _result("ALLOW", 0, ["Ordinary text generation does not access a protected resource."])

    score = calculate_risk(a)
    permission = _normalize(a.get("permission_status", "unknown"))
    verified = a.get("resource_verified") is True
    prohibited = a.get("policy_prohibited") is True
    destination = _normalize(a.get("destination_risk") or a.get("destination_category") or "unknown")
    operation = _normalize(a.get("operation", "unknown"))

    # High-impact destructive actions are denied, not merely sent for review.
    # This check intentionally runs before unverified-resource handling so an
    # unknown resource cannot turn a destructive request into an approval.
    if _is_destructive_request(a):
        return _result(
            "BLOCK",
            100,
            [
                "Destructive actions are denied by the demo policy.",
                "The request was not executed; no production system was contacted.",
            ],
        )

    # A maximum risk score is a hard stop. Lower high-risk scores can still
    # require review, but a score of 100 must never be shown as an approval.
    if score >= 100:
        return _result(
            "BLOCK",
            100,
            [
                "Risk score reached 100/100, which meets the hard-block threshold.",
                "The request was not executed; no production system was contacted.",
            ],
        )

    # Hard constraints take priority over a numerical risk threshold.
    if prohibited or destination == "prohibited":
        return _result("BLOCK", 100, a.get("context_reasons") or ["The request violates a prohibited policy or destination rule."])
    # A known denial is a block. Unknown permission/resource state is not proof
    # of malicious intent: it must be reviewed, and it must never be executed.
    if permission == "denied":
        return _result("BLOCK", 100, a.get("context_reasons") or ["The trusted registry explicitly denied this permission."])
    if not verified or permission != "granted":
        # An explicitly named local .txt file that is absent from the trusted
        # registry is denied. Vague resource descriptions can still go to review.
        resource_name = _normalize(a.get("resource", ""))
        description = _normalize(a.get("action_description", ""))
        explicit_filename = (
            resource_name.endswith(".txt")
            or any(token.endswith(".txt") for token in description.split())
        )
        context_reasons = a.get("context_reasons") or []
        registry_failed = any(
            "no unique file" in _normalize(reason)
            or "no trusted policy metadata" in _normalize(reason)
            for reason in context_reasons
        )
        if not verified and explicit_filename and registry_failed:
            return _result(
                "BLOCK",
                max(60, score),
                (a.get("context_reasons") or [])
                + ["The explicitly named file is not verified in the approved demo registry."],
            )
        return _result("APPROVAL", max(30, score), (a.get("context_reasons") or []) + ["The resource or permission could not be verified. Clarify the request or review the resource policy before proceeding."])
    if operation in {"", "unknown", "none"}:
        return _result("APPROVAL", max(60, score), ["The requested operation could not be identified confidently.", "Human review is required."])
    if bool(a.get("uncertain", False)) or bool(a.get("missing_information")):
        return _result("APPROVAL", max(30, score), ["The request is uncertain or required information is missing."])
    if score >= 30:
        return _result("APPROVAL", score, [f"Risk score {score} meets the review threshold of 30."])
    return _result("ALLOW", score, ["Resource is verified, permission is granted, required details are present, and risk is below 30."])
