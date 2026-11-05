
# AscSentinel - Context and Resource Registry
# Simulation only: does not access real company systems or execute actions.

import json
import os
import re
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DEMO_DIR = (BASE_DIR / "demo_files").resolve()
POLICY_FILE = BASE_DIR / "resource_policy.json"

DEMO_USER = {
    "user_id": "demo_user",
    "roles": ["employee"],
}


def _normalize(value):
    return re.sub(r"\s+", " ", str(value or "").strip().lower())


def _load_policy():
    try:
        with POLICY_FILE.open("r", encoding="utf-8") as file:
            policy = json.load(file)
        return policy if isinstance(policy, dict) else {"resources": {}}
    except (OSError, json.JSONDecodeError):
        return {"resources": {}}


def _get_operation(analysis):
    operation = _normalize(analysis.get("operation", "unknown"))

    aliases = {
        "open": "read",
        "view": "read",
        "search": "search",
        "create": "write",
        "edit": "write",
        "modify": "write",
        "delete": "delete",
        "remove": "delete",
        "upload": "upload",
        "send": "transfer",
    }

    return aliases.get(operation, operation)


def _is_non_file_task(analysis):
    """Recognize tasks that do not require a local file."""
    intent = _normalize(analysis.get("intent_category"))
    operation = _get_operation(analysis)

    if intent == "creative_writing":
        return True

    return (
        intent == "general_information"
        and operation in {"search", "answer", "explain"}
        and _normalize(analysis.get("destination"))
        in {"public_web", "google", "web", "internet"}
    )


def _safe_non_file_context(analysis):
    """Context for a non-file task; policy checks still decide the outcome."""
    intent = _normalize(analysis.get("intent_category"))

    return {
        "matched_resource": None,
        "matched_destination": None,
        "resource_verified": True,
        "resource_classification": "public",
        "permission_status": "granted",
        "destination_risk": "trusted",
        "policy_prohibited": False,
        "security_checks_status": "passed",
        "context_reasons": [
            (
                "Creative-writing request; no local file is required."
                if intent == "creative_writing"
                else "Public-information request; no local file is required."
            )
        ],
        "simulation": True,
    }


def _resolve_file_resource(analysis):
    """Match an explicitly named file within demo_files only."""
    if not DEMO_DIR.is_dir():
        return None, "The approved demo directory does not exist."

    policy = _load_policy()
    resources = policy.get("resources", {})
    if not isinstance(resources, dict):
        resources = {}

    description = str(analysis.get("action_description", ""))
    resource = str(analysis.get("resource", "")).strip()

    # Prefer a specific resource name. If the analyzer supplied the whole
    # sentence, recover only an explicitly named .txt file from that sentence.
    candidates = []
    if resource and _normalize(resource) not in {
        "unknown", "none", "public information"
    }:
        candidates.append(resource)
    for source in (resource, description):
        candidates.extend(
            re.findall(
                r"(?<![\w./-])[A-Za-z0-9_.-]+\.txt(?![\w.-])",
                source,
                flags=re.IGNORECASE,
            )
        )

    # Only accept names that actually exist inside demo_files.
    matches = []
    for candidate in candidates:
        # Reject absolute paths and traversal attempts.
        candidate_path = Path(candidate)
        if candidate_path.is_absolute() or ".." in candidate_path.parts:
            continue

        try:
            resolved = (DEMO_DIR / candidate_path).resolve()
            resolved.relative_to(DEMO_DIR)
        except (ValueError, OSError):
            continue

        if resolved.is_file():
            relative_name = resolved.relative_to(DEMO_DIR).as_posix()
            matches.append(relative_name)

    matches = list(dict.fromkeys(matches))

    if len(matches) != 1:
        return None, "No unique file was identified in the approved demo directory."

    filename = matches[0]
    metadata = resources.get(filename)

    if not isinstance(metadata, dict):
        return None, (
            f"{filename} exists but has no trusted policy metadata."
        )

    return {
        "filename": filename,
        "metadata": metadata,
    }, None


def resolve_context(analysis):
    """
    Resolve resource and permission context for policy_engine.py.

    This function never authorizes execution. It only provides context.
    """
    analysis = dict(analysis or {})
    operation = _get_operation(analysis)
    intent = _normalize(analysis.get("intent_category"))

    # Non-file tasks do not need to match a local file.
    if _is_non_file_task(analysis):
        return _safe_non_file_context(analysis)

    # File and protected-resource operations use the local policy registry.
    result, error = _resolve_file_resource(analysis)

    if error:
        return {
            "matched_resource": None,
            "matched_destination": None,
            "resource_verified": False,
            "resource_classification": "unknown",
            "permission_status": "unknown",
            "destination_risk": "unknown",
            "policy_prohibited": False,
            "security_checks_status": "failed",
            "context_reasons": [
                error,
                "Unknown or unverified resources must not be automatically trusted.",
            ],
            "simulation": True,
        }

    filename = result["filename"]
    metadata = result["metadata"]
    classification = _normalize(
        metadata.get("classification", "unknown")
    )
    roles = metadata.get("allowed_roles", [])
    operations = metadata.get("allowed_operations", [])

    user_roles = set(DEMO_USER["roles"])
    allowed_roles = {
        _normalize(role) for role in roles
    } if isinstance(roles, list) else set()
    allowed_operations = {
        _normalize(item) for item in operations
    } if isinstance(operations, list) else set()

    # Use canonical operations for permission checks.
    operation_for_policy = operation
    if operation_for_policy in {"open", "view", "search"}:
        operation_for_policy = "read"

    permitted = (
        bool(user_roles & allowed_roles)
        and operation_for_policy in allowed_operations
    )

    return {
        "matched_resource": filename,
        "matched_destination": None,
        "resource_verified": True,
        "resource_classification": classification,
        "permission_status": "granted" if permitted else "denied",
        "destination_risk": "trusted",
        "policy_prohibited": not permitted,
        "security_checks_status": "passed" if permitted else "failed",
        "context_reasons": [
            (
                f"{filename} is registered as {classification}; "
                "the user role and operation are authorized."
                if permitted
                else
                f"The user's role is not authorized to {operation_for_policy} "
                f"{filename}."
            )
        ],
        "simulation": True,
    }
