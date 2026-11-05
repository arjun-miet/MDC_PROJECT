"""Regression tests for natural-language custom descriptions."""
import unittest
from context_registry import resolve_context
from policy_engine import evaluate_action

class CustomDescriptionTests(unittest.TestCase):
    def test_vague_custom_resource_goes_to_approval_not_block(self):
        # Represents the analyzer output for a vague but potentially legitimate
        # request such as "Read a public document from the company knowledge base".
        analysis = {
            "operation": "read",
            "resource": "company knowledge base",
            "intent_category": "general_information",
            "data_sensitivity": "public",
            "destination_category": "external",
            "action_impact": "low",
            "uncertain": False,
            "missing_information": [],
            "action_description": "Read a public document from the company knowledge base.",
        }
        context = resolve_context(analysis)
        result = evaluate_action({**analysis, **context, "action_description": analysis["action_description"]})
        self.assertEqual(result["decision"], "APPROVAL", result)
        self.assertFalse(result["executed"])

    def test_unregistered_explicit_filename_stays_blocked(self):
        analysis = {
            "operation": "read", "resource": "secret_unknown_file.txt",
            "intent_category": "read_only", "action_description": "Read secret_unknown_file.txt"
        }
        context = resolve_context(analysis)
        result = evaluate_action({**analysis, **context})
        self.assertEqual(result["decision"], "BLOCK", result)

    def test_safe_text_task_does_not_need_resource(self):
        result = evaluate_action({"intent_category": "creative_writing", "action_description": "Write a poem about autumn"})
        self.assertEqual(result["decision"], "ALLOW", result)
        self.assertFalse(result["executed"])

if __name__ == "__main__":
    unittest.main()
