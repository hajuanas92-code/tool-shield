"""The firewall's request/response formats. /v1/tool-call has not changed since step 3."""
from typing import Any, Optional

from pydantic import BaseModel, Field

from decision import Verdict


class ToolCallRequest(BaseModel):
    agent_id: str
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    context: list[str] = Field(default_factory=list)  # untrusted text the agent has read


class ToolCallResponse(BaseModel):
    call_id: int
    verdict: Verdict
    reason: str
    risk_score: Optional[float] = None


class ExecuteResponse(ToolCallResponse):
    """Proxy mode: same fields as above, plus the tool's output (only when the call was ALLOWED and ran)."""
    result: Optional[Any] = None
    error: Optional[str] = None