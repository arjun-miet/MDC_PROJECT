# AscSentinel
### AI Agent Runtime Security & Adversarial Testing Platform

AscSentinel is a runtime security gateway and adversarial testing platform designed to secure AI agents that interact with external tools and business systems.

It acts as a controlled enforcement layer between an AI agent and its tools. Every proposed action is evaluated against deterministic security policies before execution, helping prevent unauthorized access, unsafe operations, and data exfiltration.

---

## Overview

AI agents can perform tasks such as retrieving customer records, sending emails, and initiating financial transactions. However, an agent may be manipulated through indirect prompt injection, malicious instructions, or excessive permissions.

AscSentinel addresses these risks by ensuring that the AI agent does not execute tools directly. Instead, all tool requests pass through a security gateway that evaluates permissions, validates arguments, applies policy constraints, and records decisions.

### Key Objectives

- Enforce authorization before tool execution.
- Reduce risks caused by prompt injection and excessive agency.
- Apply deterministic security policies independent of model reasoning.
- Support human approval for sensitive actions.
- Maintain tamper-evident audit records.
- Evaluate agent behavior against synthetic adversarial scenarios.

---

## Architecture

```text
                 User Task / Adversarial Prompt
                              |
                              v
                     +------------------+
                     |    AI Agent      |
                     |  Bounded ReAct    |
                     +------------------+
                              |
                              v
                     Tool Call Proposal
                              |
                              v
              +--------------------------------+
              |    AscSentinel Security        |
              |           Gateway              |
              +--------------------------------+
                              |
              +--------------------------------+
              | Context & Identity Validation  |
              | Deterministic Policy Engine    |
              | RBAC Authorization             |
              | Argument Validation            |
              | DLP Heuristics                 |
              | Domain Allowlist               |
              +--------------------------------+
                              |
                 +------------+------------+
                 |            |            |
                 v            v            v
               BLOCK     REQUIRE_APPROVAL  ALLOW
                 |            |            |
                 v            v            v
              Audit Log    Human Review   Tool Execution
                 |            |            |
                 +------------+------------+
                              |
                              v
                    Sanitized Tool Result
                              |
                              v
                         AI Agent
```

---

## Core Features

### 1. Runtime Security Gateway
Intercepts agent tool requests and evaluates them before execution.

### 2. Deterministic Policy Engine
Uses YAML-based policies to enforce:
- Role-based access control (RBAC)
- Tool permissions
- Parameter constraints
- Strict argument validation
- Data loss prevention heuristics
- Domain allowlist verification
- Deny-by-default behavior

### 3. Human-in-the-Loop (HITL)
Sensitive actions can be paused for approval. Approval is associated with the specific tool call and argument hash, expires after a configured time, and is single-use.

### 4. Simulated Business Tools
AscSentinel includes simulated tools for demonstrating security enforcement:

| Tool | Description |
|---|---|
| `get_customer` | Retrieve synthetic customer information |
| `send_email` | Simulate sending an email |
| `issue_refund` | Simulate issuing a refund |

### 5. Cryptographic Audit Ledger
Records security decisions using a SHA-256 hash chain to make in-place modifications detectable.

The ledger is tamper-evident, not immutable. An unanchored ledger may be vulnerable to tail truncation by an attacker with local disk access.

### 6. Adversarial Security Evaluation
Evaluates agent behavior against synthetic scenarios, including:
- Unauthorized refund attempts
- External email exfiltration
- Role and permission violations
- Malicious instructions
- Legitimate business tasks

Evaluation results should be interpreted within the scope of the configured synthetic test dataset.

---

## Technology Stack

| Component | Technology |
|---|---|
| Language | Python |
| Policy Configuration | YAML |
| Data Validation | Pydantic |
| Audit Storage | SQLite |
| Audit Integrity | SHA-256 Hash Chain |
| AI Provider | Google Gemini API |
| Offline Testing | Mock LLM Provider |
| Testing | Pytest |

---

## Project Structure

```text
AscSentinel/
├── asc sentinel/
│   └── agent/
│       ├── providers.py
│       ├── orchestrator.py
│       ├── evaluator.py
│       └── tools_schema.py
├── config/
│   └── policies.yaml
├── tests/
├── data/
├── run_demo.py
├── run_agent_cli.py
├── requirements.txt
├── .env.example
└── README.md
```

> Adjust the directory names above to match the actual project structure.

---

## Installation

### Prerequisites

- Python 3.10 or newer
- Git (optional)
- Google Gemini API key for live model integration

### 1. Navigate to the Project

```powershell
cd "$HOME\.gemini\antigravity\scratch\AscSentinel"
```

### 2. Create a Virtual Environment

```powershell
python -m venv .venv
```

### 3. Install Dependencies

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

---

## Configuration

Create a `.env` file by copying the example:

```powershell
Copy-Item .env.example .env
```

Edit `.env`:

```dotenv
LLM_PROVIDER=mock

GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-2.5-flash

POLICY_CONFIG_PATH=config/policies.yaml
AUDIT_DB_PATH=data/audit.db
```

For live Gemini integration, set:

```dotenv
LLM_PROVIDER=gemini
```

Replace the placeholder with your own API key.

**Security:** Never commit `.env` or expose API keys in screenshots, logs, or public repositories. Keep `.env.example` limited to placeholders.

---

## Running AscSentinel

### 1. Run the Demonstration

```powershell
.\.venv\Scripts\python.exe run_demo.py
```

The demonstration showcases:
- Authorized customer lookup
- Unauthorized action blocking
- Human approval workflow
- External email restriction
- Audit chain verification
- Baseline versus gateway comparison

### 2. Run the Interactive Agent

```powershell
.\.venv\Scripts\python.exe run_agent_cli.py
```

The interactive CLI allows users to submit tasks, inspect proposed tool calls, view gateway decisions, and handle approval requests.

### 3. Run the Agent Evaluation

```powershell
.\.venv\Scripts\python.exe run_agent_cli.py --evaluate
```

Runs the configured synthetic agent security evaluation.

### 4. Run the Smoke Test

```powershell
.\.venv\Scripts\python.exe run_agent_cli.py --smoke-test
```

### 5. Run the Test Suite

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

---

## Security Model

AscSentinel separates the agent’s reasoning from tool execution.

| Trust Zone | Description |
|---|---|
| Untrusted Input | User prompts, external communications, and retrieved content |
| Semi-Trusted Agent | LLM reasoning and proposed tool calls |
| Trusted Enforcement | Gateway, policy engine, and private tool dispatcher |

The LLM is not trusted to determine its own permissions. Roles and execution context are supplied by the application, and all tool side effects must pass through the gateway.

---

## Limitations

AscSentinel is an academic prototype and does not provide complete protection against every form of prompt injection.

- Evaluation uses synthetic scenarios and does not represent universal attack coverage.
- DLP relies on heuristic pattern matching and may miss encoded or novel exfiltration.
- The SQLite hash chain is not externally anchored.
- Application-level mediation does not replace OS-level sandboxing or container isolation.
- Live model behavior may vary by provider and model version.
- Security evaluation results depend on correct scenario classification and execution tracking.

---

## Future Enhancements

- Web-based security monitoring dashboard
- Remote audit-log anchoring
- More comprehensive adversarial datasets
- Advanced DLP and semantic detection
- Additional AI model providers
- Container-level tool isolation
- Expanded policy testing and coverage metrics

---

## Research and Demonstration Scope

AscSentinel demonstrates how deterministic runtime enforcement can reduce reliance on an AI model’s own safety reasoning when performing tool-augmented tasks.

Its primary contribution is the mediation of tool execution through policy enforcement, controlled approvals, and auditability.


