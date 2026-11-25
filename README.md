# ToolShield

**ToolShield**. Just as the name suggests, it acts as a protective shield—a security layer sitting between an autonomous AI agent and the tools it uses, such as querying databases, sending emails, or issuing refunds. 

When an AI agent processes external inputs, attackers can hide malicious prompt injections inside emails to trick the AI into issuing unauthorized $9,500 refunds or wiping out the entire database. ToolShield is built to stop these attacks using five core layers: 

**1. Lightweight ML Classifier:**
ToolShield uses a machine-learning model built with **TF-IDF vectorization and Logistic Regression** from scikit-learn. It converts incoming emails into word and character patterns to calculate a risk probability from **0.00 to 1.00** that an email contains a prompt injection. 

**2. Deterministic Policy Rules:**
This is our main shield, checking strict rules in just **0.14 milliseconds**. It uses SQL parsing to block destructive commands like `DROP TABLE` or `DELETE` without a `WHERE` clause, blocks refunds greater than **$1,000**, restricts outgoing emails to approved domains, and blocks dangerous shell commands like `curl | sh`. 

👉 **[ACTION 1 — Run the Attack Table Demo]**
*(Run `python demo_attacks.py` in Terminal 3)* 

"Let's see those first two layers in action. Safe SQL reads and small refunds get a green `ALLOW`, while `DROP TABLE`, bad domains, and the $9,500 refund are blocked by our policy rules. And on the last row, a small $60 refund triggered right after a poisoned email is caught by our ML classifier at `risk=1.00` and blocked." 

**3. Proxy Execution Architecture:**
The AI agent has **zero direct access** to the database or email system. Only the ToolShield firewall holds the credentials and executes approved tool calls on the agent's behalf. Even if a hacker hijacks the AI's brain, the firewall protects the database and sensitive data. 

**4. Human-in-the-Loop Approval:**
Medium-risk actions—like a **$500 refund**—are paused and locked in SQLite until an admin reviews and approves or denies them. Once approved, the firewall runs the exact locked arguments **once**, making it impossible for the AI to swap $500 to $9,500 after approval. 

👉 **[ACTION 2 — Run the Live AI Agent + Approval Watch]**
*(Make sure Terminal 1 is running `uvicorn --app-dir firewall main:app --port 8000` and Terminal 2 is running `python cli.py watch`. Now run this in Terminal 3:)* 

```bash
python agent/agent.py "Query SELECT id, amount FROM orders WHERE amount > 200 AND amount < 900 LIMIT 1, then issue a full refund for that exact order."
```

"Here, our live Groq AI agent finds Order #3 for $537.59 and tries to refund it. Because it's over $100, ToolShield pauses the agent (`WAIT`) and alerts my admin terminal." 

*(Switch to Terminal 2, type **`y`**, and press **Enter**)* 

"Once I approve it, the firewall executes those exact locked arguments once and returns the result so the AI can finish its reply." 

**5. Audit Logs & OpenTelemetry:**
Finally, ToolShield saves a permanent audit trail of every tool call and sends live latency traces to **Jaeger** when running in Docker, helping developers monitor every single decision." 

👉 **[ACTION 3 — Optional: Show Jaeger or Eval Table]**
*(Briefly switch to `http://localhost:16686` in your browser if Docker is running, or show `eval/results.md` in your editor before wrapping up.)*
