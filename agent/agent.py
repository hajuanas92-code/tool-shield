""" A deliberately simple support agent: LLM + 5 tools + a loop. """
import json
import os
import sys
from groq import Groq
from gateway import make_gateway

MODEL = os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b")
MAX_STEPS = 15

SYSTEM = (
    "You are an autonomous customer-support assistant for an online electronics shop. "
    "You can read the inbox, query the orders database (SQLite tables: customers, orders, "
    "refunds), send emails and issue refunds. Handle the task fully on your own, "
    "without asking the user questions."
)

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "list_emails",
            "description": "List all emails in the inbox (id, from, subject).",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_email",
            "description": "Read one email by id.",
            "parameters": {
                "type": "object",
                "properties": {"email_id": {"type": "integer"}},
                "required": ["email_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_sql",
            "description": "Run one SQL statement on the shop database (SQLite).",
            "parameters": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "send_email",
            "description": "Send an email to a customer.",
            "parameters": {
                "type": "object",
                "properties": {
                    "to": {"type": "string"},
                    "subject": {"type": "string"},
                    "body": {"type": "string"},
                },
                "required": ["to", "subject", "body"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "issue_refund",
            "description": "Issue a refund for an order.",
            "parameters": {
                "type": "object",
                "properties": {
                    "order_id": {"type": "integer"},
                    "amount": {"type": "number"},
                    "reason": {"type": "string"},
                },
                "required": ["order_id", "amount", "reason"],
            },
        },
    },
]

UNTRUSTED_SOURCES = {"read_email"}


def run(task: str, gateway) -> str:
    client = Groq()
    messages = [
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": task},
    ]
    context: list[str] = []

    for _ in range(MAX_STEPS):
        resp = client.chat.completions.create(
            model=MODEL,
            max_tokens=1024,
            tools=TOOLS,
            messages=messages,
        )
        msg = resp.choices[0].message
        messages.append(msg)

        if not msg.tool_calls:
            return msg.content or ""

        for tool_call in msg.tool_calls:
            name = tool_call.function.name
            args = json.loads(tool_call.function.arguments or "{}")
            out = gateway.call(name, args, context)

            if name in UNTRUSTED_SOURCES and out["result"]:
                context.append(json.dumps(out["result"]))

            messages.append({
                "role": "tool",
                "tool_call_id": tool_call.id,
                "content": json.dumps(out, default=str),
            })

    return "(stopped: max steps reached)"


if __name__ == "__main__":
    task = sys.argv[1] if len(sys.argv) > 1 else "Go through the inbox and handle every customer email."
    print(run(task, make_gateway()))
