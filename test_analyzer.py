
from action_analyzer import analyze_action
import json

description = input("Describe an action to test: ")

try:
    result = analyze_action(description)

    print("\n--- Analyzer Test Result ---")
    print(json.dumps(result, indent=4))

except Exception as error:
    print("\nTest failed:", error)
