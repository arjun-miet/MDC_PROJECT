"""Offline unit tests for the deterministic policy engine; no Ollama required."""
import unittest
from policy_engine import calculate_risk, evaluate_action


def request(**overrides):
    data = {
        "intent_category": "read_only",
        "operation": "read",
        "resource": "public_guide.txt",
        "resource_classification": "public",
        "destination_risk": "trusted",
        "action_impact": "low",
        "resource_verified": True,
        "permission_status": "granted",
        "policy_prohibited": False,
        "uncertain": False,
        "missing_information": [],
        "action_description": "Read public_guide.txt",
    }
    data.update(overrides)
    return data


class RiskScoreTests(unittest.TestCase):
    def test_safe_public_read_scores_zero(self):
        self.assertEqual(calculate_risk(request()), 0)

    def test_internal_resource_adds_ten(self):
        self.assertEqual(calculate_risk(request(resource_classification="internal")), 10)

    def test_confidential_external_transfer_adds_combined_risk(self):
        data = request(resource_classification="confidential", destination_risk="known_external", operation="transfer", action_impact="high")
        self.assertEqual(calculate_risk(data), 80)

    def test_score_is_capped_at_100(self):
        data = request(resource_classification="restricted", destination_risk="unknown", action_impact="high", uncertain=True, missing_information=["destination"], intent_category="destructive", operation="delete", action_description="delete restricted records")
        self.assertEqual(calculate_risk(data), 100)


class PolicyDecisionTests(unittest.TestCase):
    def test_authorized_safe_request_is_allowed(self):
        self.assertEqual(evaluate_action(request())["decision"], "ALLOW")

    def test_unauthorized_access_is_blocked(self):
        result = evaluate_action(request(resource_classification="restricted", permission_status="denied"))
        self.assertEqual(result["decision"], "BLOCK")
        self.assertEqual(result["risk_score"], 100)

    def test_prohibited_destination_is_blocked(self):
        self.assertEqual(evaluate_action(request(destination_risk="prohibited", operation="transfer"))["decision"], "BLOCK")

    def test_unverified_resource_requires_approval_if_permission_granted(self):
        self.assertEqual(evaluate_action(request(resource_verified=False))["decision"], "APPROVAL")

    def test_missing_information_requires_approval(self):
        self.assertEqual(evaluate_action(request(missing_information=["destination"]))["decision"], "APPROVAL")

    def test_elevated_risk_requires_approval(self):
        data = request(resource_classification="confidential", destination_risk="known_external", operation="transfer", action_impact="high")
        self.assertEqual(evaluate_action(data)["decision"], "APPROVAL")

    def test_creative_writing_does_not_need_a_file(self):
        data = request(intent_category="creative_writing", operation="generate", resource_verified=False, permission_status="unknown")
        self.assertEqual(evaluate_action(data)["decision"], "ALLOW")



    def test_maximum_risk_score_is_blocked(self):
        data = request(
            resource_classification="restricted",
            destination_risk="unknown",
            action_impact="high",
            uncertain=True,
            missing_information=["destination"],
            intent_category="destructive",
            operation="delete",
            action_description="Delete all records from the production database permanently.",
            resource_verified=False,
            permission_status="unknown",
        )
        result = evaluate_action(data)
        self.assertEqual(result["risk_score"], 100, result)
        self.assertEqual(result["decision"], "BLOCK", result)
        self.assertFalse(result["executed"])

    def test_destructive_action_is_blocked_even_when_resource_is_unverified(self):
        data = request(
            operation="delete",
            intent_category="destructive",
            action_description="Delete all records from the production database permanently.",
            resource_verified=False,
            permission_status="unknown",
        )
        result = evaluate_action(data)
        self.assertEqual(result["decision"], "BLOCK", result)
        self.assertFalse(result["executed"])

    def test_every_decision_is_simulation_only(self):
        for data in (request(), request(permission_status="denied"), request(missing_information=["destination"])):
            result = evaluate_action(data)
            self.assertFalse(result["executed"])
            self.assertTrue(result["simulation"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
