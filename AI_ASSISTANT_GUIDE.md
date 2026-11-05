# AscSentinel AI Assistant — integration notes

## Intended flow

1. The user asks the AI Assistant for a task in natural language.
2. Ollama (`llama3.2:3b`) turns the request into one constrained task plan. The model does not make authorization decisions.
3. AscSentinel's deterministic `evaluate_action` policy engine decides `ALLOW`, `BLOCK`, or `APPROVAL` for each resource action.
4. `ALLOW`: the backend executes the supported action inside `demo_files` and records the result.
5. `BLOCK`: the backend does not perform the action.
6. `APPROVAL`: the task and exact resource arguments are stored with the pending audit record; no task is performed until a reviewer approves it. The review endpoint then executes the stored, bounded task and returns its result.
7. A separate audit record captures successful execution after approval.

`Evaluate Request` remains simulation-only. It never creates, edits, or reads files as a side effect.

## Supported AI assistant actions

- Friendly chat and greetings; multilingual responses are requested from the local model.
- List `.txt` files in the app-owned `demo_files` workspace.
- Create a new `.txt` file (empty files are allowed when explicitly requested; existing files are never overwritten).
- Summarize a file, answer a question from a file, or compare two files.
- All file paths are restricted to the workspace; document contents are treated as untrusted input, not instructions.

No arbitrary shell execution, Python execution, deletion, overwriting, or external transfer is exposed as an AI tool.

## Personalization and privacy

The browser stores the recent chat and a name if the user tells the assistant one, using local storage. The recent chat and saved name are sent to the local assistant endpoint for continuity. This is browser-local convenience memory, not a server-side identity system; clearing the browser's site data removes it. Do not use this as authentication or authorization.

## Run locally

```bash
python -m pip install -r requirements.txt
ollama pull llama3.2:3b
python app.py
```

Open `http://127.0.0.1:5000`. Keep Ollama running. Use the Review Queue to approve/reject pending actions. Only approve requests you understand and intend to authorize.

## Validation notes

`app.py` compiles with Python syntax checking. Run the included tests from the project folder after installing dependencies. Some pre-existing scenario tests may depend on the app's configured database/workspace and the Ollama package; failures in those tests should be investigated in the actual local environment before a live demo.
