# AscSentinel AI Assistant update

## What changed

- The Request Simulator (`POST /api/evaluate`) remains simulation-only and does not execute file operations.
- The AI Workspace uses the local Ollama model `llama3.2:3b` to classify a request into a limited, explicit tool plan.
- Supported assistant tools: list `.txt` files in `demo_files`, create a new `.txt` file, summarize a file, compare two files, and answer questions grounded in a file.
- Actual workspace actions pass through the deterministic policy engine. `BLOCK` never executes. `APPROVAL` pauses and stores an action-specific task with its audit item. Once a reviewer approves the exact audit item, the create-file task is executed; rejected or pending tasks are not executed.
- New files are created only inside `demo_files`, limited to 20 KB, and never overwrite an existing file. No shell execution, deletion, arbitrary path access, or external transfers are exposed as tools.
- The browser keeps the recent chat transcript and a user name (when explicitly shared) in local storage so the assistant can use that context after a refresh on the same browser. This is local browser memory, not cross-device/account memory. Users should not enter secrets into the chat.
- The assistant is prompted to respond in the language the user uses and to be friendly. Language coverage depends on the installed local model; it cannot be guaranteed for every language.

## Run

From the `ASCSentinel_REPAIRED` folder:

```bash
python -m pip install -r requirements.txt
ollama pull llama3.2:3b
python app.py
```

Open `http://127.0.0.1:5000`.

## Manual acceptance checks

1. In Request Simulator, submit a create-file request. Verify it only returns a policy decision and does not create a file.
2. In AI Workspace, ask: `Create a file named raj1 with the text Hello from AscSentinel`. If policy returns `ALLOW`, `demo_files/raj1.txt` should be created.
3. Ask `List all files`. Verify `raj1.txt` appears.
4. Ask to create a file with sensitive-looking content, such as a payroll/secret note. It should be held for review when the policy engine returns `APPROVAL`.
5. Approve that specific audit item in Review Queue. The file should be created only after approval; reject it in a separate test and verify no file is created.
6. Ask to read `restricted_payroll.txt` as the employee role. The policy should block access and the file contents must not be read.
7. Try a path such as `../../outside.txt`, an overwrite request, or a shell command. These must not execute.

The included app requires Flask and Ollama installed locally to run endpoint-level tests. Python syntax and frontend JavaScript syntax were checked during packaging.
