
# AscSentinel - Simulated Security Checks
#
# IMPORTANT:
# This is a local demonstration, not a real identity
# provider or production authorization system.

DEMO_USER = "demo_user"

# Trusted demo records: these values are configured here,
# not accepted from the user's natural-language claims.
RESOURCES = {
    "public document": {
        "sensitivity": "public"
    },
    "customer records": {
        "sensitivity": "confidential"
    }
}

DESTINATIONS = {
    "trusted company server": {
        "risk": "trusted"
    },
    "personal email": {
        "risk": "known_external"
    }
}


def normalize(value):
    return " ".join(value.lower().strip().split())


def check_security(analysis):
    """
    Apply local demo checks to an AI-extracted action.
    Unknown resources or destinations remain unverified.
    """

    resource_text = normalize(analysis.get("resource", ""))
    destination_text = normalize(analysis.get("destination", ""))

    resource_record = next(
        (
            record for name, record in RESOURCES.items()
            if name in resource_text
        ),
        None
    )

    destination_record = next(
        (
            record for name, record in DESTINATIONS.items()
            if name in destination_text
        ),
        None
    )

    # Never trust the AI's sensitivity estimate when a
    # resource has a trusted classification in our registry.
    if resource_record is None:
        sensitivity = "unknown"
    else:
        sensitivity = resource_record["sensitivity"]

    if destination_record is None:
        destination_risk = "unknown"
    else:
        destination_risk = destination_record["risk"]

    operation = normalize(analysis.get("operation", ""))

    # Explicitly limited demo permissions.
    # Unknown operations/resources/destinations are not allowed.
    if (
        operation in {"read", "view", "open"}
        and resource_record is not None
        and resource_record["sensitivity"] == "public"
        and destination_record is not None
        and destination_record["risk"] == "trusted"
    ):
        permission_status = "granted"
    else:
        permission_status = "unknown"

    checks_verified = (
        resource_record is not None
        and destination_record is not None
    )

    return {
        "principal": DEMO_USER,
        "data_sensitivity": sensitivity,
        "destination_risk": destination_risk,
        "permission_status": permission_status,
        "security_checks_status": (
            "verified" if checks_verified else "unverified"
        ),
        "policy_prohibited": (
            destination_risk == "prohibited"
        ),
        "simulation": True
    }
