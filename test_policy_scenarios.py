"""Predefined end-to-end policy scenarios using the real demo registry.

These tests bypass the LLM so failures identify policy/registry behavior rather
than model variability. No real file action is performed.
"""
import unittest
from context_registry import resolve_context
from policy_engine import evaluate_action


def evaluate_scenario(description, operation, intent="read_only", impact="low", uncertain=False, missing=None, destination=""):
    analysis = {
        "action_description": description,
        "operation": operation,
        "resource": description,
        "destination": destination,
        "intent_category": intent,
        "data_sensitivity": "unknown",
        "destination_category": "unknown",
        "action_impact": impact,
        "uncertain": uncertain,
        "missing_information": missing or [],
    }
    context = resolve_context(analysis)
    return evaluate_action({**analysis, **context, "action_description": description})


class PredefinedScenarioTests(unittest.TestCase):
    def test_safe_public_guide_read_is_allowed(self):
        result = evaluate_scenario("Read public_guide.txt", "read")
        self.assertEqual(result["decision"], "ALLOW", result)

    def test_safe_internal_notes_read_is_allowed(self):
        result = evaluate_scenario("Read internal_notes.txt", "read")
        self.assertEqual(result["decision"], "ALLOW", result)

    def test_employee_cannot_read_restricted_payroll(self):
        result = evaluate_scenario("Read restricted_payroll.txt", "read")
        self.assertEqual(result["decision"], "BLOCK", result)

    def test_unknown_file_is_blocked(self):
        result = evaluate_scenario("Read secret_unknown_file.txt", "read")
        self.assertEqual(result["decision"], "BLOCK", result)

    def test_public_guide_to_personal_email_is_blocked_by_destination_policy(self):
        result = evaluate_scenario(
            "Transfer public_guide.txt to my personal email",
            "transfer", intent="data_transfer", impact="medium",
            destination="personal email",
        )
        self.assertEqual(result["decision"], "BLOCK", result)

    def test_missing_required_detail_is_sent_for_approval(self):
        analysis = {
            "intent_category": "read_only", "operation": "read",
            "resource": "public_guide.txt", "action_description": "Read public_guide.txt",
            "resource_verified": True, "permission_status": "granted",
            "policy_prohibited": False, "resource_classification": "public",
            "destination_risk": "trusted", "action_impact": "low",
            "uncertain": False, "missing_information": ["purpose"],
        }
        self.assertEqual(evaluate_action(analysis)["decision"], "APPROVAL")

    def test_authorized_write_with_missing_details_requires_approval(self):
        analysis = {
            "action_description": "Write internal_notes.txt",
            "operation": "write",
            "resource": "internal_notes.txt",
            "destination": "",
            "intent_category": "modification",
            "data_sensitivity": "internal",
            "destination_category": "unknown",
            "action_impact": "medium",
            "uncertain": True,
            "missing_information": ["details"],
        }
        context = resolve_context(analysis)
        result = evaluate_action({**analysis, **context, "action_description": analysis["action_description"], "uncertain": True, "missing_information": ["details"]})
        self.assertEqual(context["permission_status"], "granted", context)
        self.assertEqual(result["decision"], "APPROVAL", result)

    def test_external_destination_is_review_not_automatic_permission_denial(self):
        analysis = {
            "action_description": "Transfer internal_notes.txt to my personal email",
            "operation": "transfer",
            "resource": "internal_notes.txt",
            "destination": "my personal email",
            "intent_category": "data_transfer",
            "data_sensitivity": "internal",
            "destination_category": "known_external",
            "action_impact": "medium",
            "uncertain": False,
            "missing_information": [],
        }
        context = resolve_context(analysis)
        # The resource policy does not permit transfer, so this must still be blocked.
        # This guards against accidentally weakening resource-level authorization.
        self.assertEqual(context["permission_status"], "denied", context)
        self.assertEqual(evaluate_action({**analysis, **context})["decision"], "BLOCK")

    def test_all_scenarios_are_simulation_only(self):
        for description, operation in [("Read public_guide.txt", "read"), ("Read restricted_payroll.txt", "read")]:
            result = evaluate_scenario(description, operation)
            self.assertFalse(result["executed"])
            self.assertTrue(result["simulation"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
