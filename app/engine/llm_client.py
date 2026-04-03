"""Unified LLM client — httpx direct call to Anthropic Messages API.

No dependency on anthropic SDK. Uses httpx + x-api-key header.
"""

import httpx
from dataclasses import dataclass, field


@dataclass
class ToolCall:
    """A single tool invocation returned by the model."""
    id: str
    name: str
    arguments: dict


@dataclass
class LLMResponse:
    """Unified response from any LLM provider."""
    content: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    stop_reason: str = "end_turn"
    usage: dict = field(default_factory=dict)


class LLMClient:
    """Anthropic Messages API client via httpx."""

    def __init__(self, model: str, api_key: str, base_url: str):
        self.model = model
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self._total_input = 0
        self._total_output = 0
        self._http = httpx.Client(timeout=120)

    def chat(self, messages: list[dict], tools: list[dict] | None = None,
             system: str | None = None) -> LLMResponse:
        body: dict = {
            "model": self.model,
            "max_tokens": 4096,
            "messages": messages,
        }
        if system:
            body["system"] = system
        if tools:
            body["tools"] = [
                {
                    "name": t["name"],
                    "description": t.get("description", ""),
                    "input_schema": t.get("input_schema", {"type": "object", "properties": {}}),
                }
                for t in tools
            ]

        resp = self._http.post(
            f"{self.base_url}/v1/messages",
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json=body,
        )
        resp.raise_for_status()
        data = resp.json()

        # Accumulate token usage
        usage_data = data.get("usage", {})
        usage = {
            "input_tokens": usage_data.get("input_tokens", 0),
            "output_tokens": usage_data.get("output_tokens", 0),
        }
        self._total_input += usage["input_tokens"]
        self._total_output += usage["output_tokens"]

        # Parse content blocks
        content_text = ""
        tool_calls = []
        for block in data.get("content", []):
            if block.get("type") == "text":
                content_text += block.get("text", "")
            elif block.get("type") == "tool_use":
                tool_calls.append(ToolCall(
                    id=block["id"],
                    name=block["name"],
                    arguments=block.get("input", {}),
                ))

        return LLMResponse(
            content=content_text,
            tool_calls=tool_calls,
            stop_reason=data.get("stop_reason", "end_turn"),
            usage=usage,
        )

    def get_usage(self) -> dict:
        return {"input_tokens": self._total_input, "output_tokens": self._total_output}


def create_llm_client(model: str, api_key: str = "",
                      base_url: str = "") -> LLMClient:
    """Factory: create LLM client with user-provided credentials."""
    if not api_key:
        raise ValueError("api_key is required for Deep Scan")
    if not base_url:
        raise ValueError("base_url is required for Deep Scan")
    return LLMClient(model=model, api_key=api_key, base_url=base_url)
