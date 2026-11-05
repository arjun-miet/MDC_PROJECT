# AscSentinel — corrected policy build

## What this fixes
- Explicit destructive actions (for example, permanently deleting production records) now return `BLOCK`.
- Any request whose deterministic risk score reaches 100/100 now returns `BLOCK`.
- A missing or unverified resource can no longer cause a destructive action to be labelled only `APPROVAL`.
- The request simulator remains simulation-only: it does not execute the submitted request.
- Regression tests cover the exact risk-100 / destructive-request bug.

## Important frontend note
The uploaded files did not include your existing `templates/index.html` or its static assets. To preserve your current dashboard design, copy your existing `templates` and `static` folders into this project folder. Do not replace them with a new template.

## Run
From this folder in your existing Python environment:

```bash
python -m pip install -r requirements.txt
ollama pull llama3.2:3b
python app.py
```

Open `http://127.0.0.1:5000`.

## Test the policy fix
```bash
python -m unittest test_policy_engine.py test_policy_scenarios.py test_custom_requests.py -v
```

Expected for `Delete all records from the production database permanently.`:
- `decision`: `BLOCK`
- `risk_score`: `100`
- `executed`: `false`
- `simulation`: `true`

This is a local demo policy, not a production authorization system. Do not connect it to a real production database.
