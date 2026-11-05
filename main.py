"""Optional command-line simulator using the same policy pipeline as app.py.

Run `python app.py` for the dashboard. This CLI also performs simulation only.
"""
import json

from action_analyzer import analyze_action
from context_registry import resolve_context
from policy_engine import evaluate_action


def main():
    print("=" * 48)
    print("              AscSentinel")
    print("      AI Analysis + Policy Evaluation")
    print("=" * 48)
    print("Simulation only: no real-world action is executed.")

    while True:
        description = input("\nDescribe an action (or type 'exit'): ").strip()
        if description.lower() == "exit":
            print("Exiting AscSentinel.")
            break
        if not description:
            print("Please enter an action description.")
            continue

        try:
            analysis = analyze_action(description)
            context = resolve_context({
                **analysis,
                "action_description": description,
            })
            policy_input = {
                **analysis,
                **context,
                "action_description": description,
            }
            decision = evaluate_action(policy_input)

            print("\n--- AI Analysis ---")
            print(json.dumps(analysis, indent=2))
            print("\n--- Trusted Security Context ---")
            print(json.dumps(context, indent=2))
            print("\n--- Policy Decision ---")
            print(json.dumps(decision, indent=2))
            print("\nNo real-world action was executed.")
        except Exception as error:
            print("\nEvaluation failed:", str(error))
            print("No real-world action was executed.")


if __name__ == "__main__":
    main()
