# ToolShield

**ToolShield** is a security firewall and execution proxy for autonomous AI agents. It sits between an LLM agent and sensitive tools—such as SQL databases, outgoing email, and payment refunds—to block prompt-injection attacks and enforce deterministic policy rules before any action runs.

## How It Works (5 Core Layers)

1. **Lightweight ML Classifier (`scikit-learn`):**
   Converts incoming untrusted text (such as customer emails) into word and character patterns using **TF-IDF vectorization + Logistic Regression** (`0.6 MB` model). It calculates a risk probability (`0.00` to `1.00`) in **0.28 ms** to catch hidden prompt injections without heavy deep-learning dependencies.
2. **Deterministic Policy Rules (`policies/default.yaml`):**
   Checks strict rules in **0.14 ms** using SQL AST parsing and allowlists—blocking `DROP TABLE`, `DELETE` without a `WHERE` clause, unauthorized tables (`sqlite_master`), refunds over `$1,000`, unapproved email domains, and shell injection (`curl | sh`).
3. **Proxy Execution Architecture (`firewall/executor.py`):**
   The AI agent has **zero direct access** to the database or email system. Only the ToolShield firewall holds the credentials and executes approved tool calls on the agent's behalf.
4. **Human-in-the-Loop Approval (`agent/cli.py`):**
   Medium-risk actions (such as refunds between `$100` and `$1,000`) are paused and their exact arguments are locked in SQLite. Once an admin approves via the CLI, the firewall executes those exact stored arguments **once**, preventing the AI from swapping arguments after approval.
5. **Audit Logs & OpenTelemetry Tracing:**
   Logs every tool call to an append-only audit trail and exports live latency spans to **Jaeger** when running in Docker.

## Evaluation Results

Tested across **307 held-out scenarios** (obvious rule attacks, disguised prompt-injection emails, benign calls, and tricky benign wording):

| Mode | Obvious Attacks Caught | Disguised Email Attacks Caught | Overall Catch Rate | False Alarms (Normal / Tricky) | p50 Latency |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Rules Only** | 100.0% | 0.0% | **23.1%** | 0.0% / 0.0% | 0.14 ms |
| **Rules + Classifier (0.5 threshold)** | 100.0% | 38.0% | **52.3%** | 0.0% / 6.5% | 1.41 ms |
| **Rules + Classifier (0.3 threshold)** | 100.0% | 59.0% | **68.5%** | 0.0% / 23.4% | 1.46 ms |

## Quick Start

### 1. Install & Train the Classifier

```bash
git clone <your-repo-url>
cd ToolShield
python -m venv venv
source venv/bin/activate        # Windows PowerShell: .\venv\Scripts\Activate.ps1
pip install -r requirements.txt

python fake_data.py
python ml/make_training_data.py
python ml/train_light.py
```

### 2. Start the Firewall Server (Terminal 1)

```bash
export ADMIN_KEY="change-me"
uvicorn --app-dir firewall main:app --port 8000
```

### 3. Run the Demos & Live Groq Agent (Terminals 2 & 3)

```bash
# Scripted 9-case policy & prompt-injection table
PYTHONPATH=agent python demo_attacks.py

# Scripted Proxy mode + locked human approval demo
export ADMIN_KEY="change-me"
python demo_proxy.py

# Interactive admin approval watcher (Terminal 2)
export ADMIN_KEY="change-me"
python agent/cli.py watch

# Live autonomous Groq AI agent (Terminal 3)
export FIREWALL_URL="http://localhost:8000"
export GROQ_API_KEY="your-groq-api-key"
python agent/agent.py "Read all emails and handle them."
```

### 4. Run with Docker & Jaeger Tracing

```bash
cp .env.example .env            # Set ADMIN_KEY inside .env
docker compose up --build
# Swagger API docs: http://localhost:8000/docs
# Jaeger Trace UI:  http://localhost:16686
```

### 5. Run Benchmarks & Automated Tests

```bash
python eval/run_eval.py --approval 0.3
python -m pytest -q
```

## Project Structure

```text
ToolShield/
├── agent/          # Groq AI agent, ProxyGateway, admin CLI, and terminal UI helpers
├── firewall/       # FastAPI proxy server, policy engine, ML classifier, SQLite executor
├── policies/       # YAML security rules (default.yaml)
├── ml/             # Synthetic dataset generator and scikit-learn training scripts
├── eval/           # Offline benchmark harness and saved metrics (results.md)
├── tests/          # 61 unit and integration tests for rules, proxy mode, and approvals
├── demo_attacks.py # 9-scenario policy & prompt-injection demo
├── demo_proxy.py   # End-to-end Proxy mode execution demo
└── fake_data.py    # Sample SQLite database and email seed generator
```

## Known Limitations

* **No per-agent API authentication yet:** While admin approval endpoints require `ADMIN_KEY`, any caller with network access to `/v1/execute` can currently submit requests under any `agent_id`.
* **Session-wide context tainting:** Once an agent reads a poisoned email, all subsequent state-changing actions in that session remain blocked or flagged until the session resets.
