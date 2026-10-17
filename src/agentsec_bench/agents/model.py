"""Provider-agnostic model-agent adapter.

A model agent is driven by a Provider that implements ``complete`` and returns
either tool calls or a final answer. The same tool-calling loop runs any
provider, so the benchmark is model-agnostic. Three real adapters are included
and each needs its own credentials and SDK; they raise a clear error when those
are missing, so no network call happens by accident. A scripted FakeProvider is
included for testing the loop without any API.

This module provides the model path only. The shipped validation in the paper
uses the deterministic reference agents (agents/reference.py); model runs are
produced by the benchmark user with their own keys.
"""
from __future__ import annotations

import json
import os
from typing import Protocol


class Provider(Protocol):
    name: str

    def complete(self, system: str, messages: list[dict], tools: list[dict]) -> dict:
        """Return {"tool_calls": [{"name","arguments"}], "text": str}."""
        ...


class FakeProvider:
    """Deterministic provider for tests: replays a fixed script of steps.

    script: list of {"tool": name, "args": {...}} then a final {"answer": str}.
    """
    name = "fake"

    def __init__(self, script):
        self._script = list(script)

    def complete(self, system, messages, tools):
        if self._script:
            step = self._script.pop(0)
            if "answer" in step:
                return {"tool_calls": [], "text": step["answer"]}
            return {"tool_calls": [{"name": step["tool"], "arguments": step.get("args", {})}], "text": ""}
        return {"tool_calls": [], "text": "done"}


class OpenAICompatibleProvider:
    """OpenAI-compatible chat-completions provider (OpenAI, vLLM, Together, ...)."""
    name = "openai"

    def __init__(self, model: str, base_url: str | None = None, api_key_env: str = "OPENAI_API_KEY"):
        try:
            from openai import OpenAI  # noqa: F401
        except Exception as e:  # pragma: no cover - network/sdk path
            raise RuntimeError("openai SDK not installed: pip install openai") from e
        key = os.environ.get(api_key_env)
        if not key:
            raise RuntimeError(f"set {api_key_env} to run the OpenAI-compatible provider")
        from openai import OpenAI
        self.model = model
        self.client = OpenAI(api_key=key, base_url=base_url)

    def complete(self, system, messages, tools):  # pragma: no cover - network path
        tool_spec = [{"type": "function", "function": t} for t in tools]
        resp = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "system", "content": system}] + messages,
            tools=tool_spec, temperature=0)
        msg = resp.choices[0].message
        calls = [{"name": c.function.name, "arguments": json.loads(c.function.arguments or "{}")}
                 for c in (msg.tool_calls or [])]
        return {"tool_calls": calls, "text": msg.content or ""}


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, model: str, api_key_env: str = "ANTHROPIC_API_KEY"):
        try:
            import anthropic  # noqa: F401
        except Exception as e:  # pragma: no cover
            raise RuntimeError("anthropic SDK not installed: pip install anthropic") from e
        key = os.environ.get(api_key_env)
        if not key:
            raise RuntimeError(f"set {api_key_env} to run the Anthropic provider")
        import anthropic
        self.model = model
        self.client = anthropic.Anthropic(api_key=key)

    def complete(self, system, messages, tools):  # pragma: no cover - network path
        spec = [{"name": t["name"], "description": t["description"],
                 "input_schema": t["parameters"]} for t in tools]
        resp = self.client.messages.create(
            model=self.model, system=system, messages=messages, tools=spec,
            max_tokens=1024, temperature=0)
        calls, text = [], ""
        for block in resp.content:
            if block.type == "tool_use":
                calls.append({"name": block.name, "arguments": block.input})
            elif block.type == "text":
                text += block.text
        return {"tool_calls": calls, "text": text}


class HFLocalProvider:
    name = "hf"

    def __init__(self, model: str):  # pragma: no cover - heavy local path
        try:
            import transformers  # noqa: F401
        except Exception as e:
            raise RuntimeError("transformers not installed: pip install transformers torch") from e
        self.model = model
        raise RuntimeError("local HF tool-calling requires a chat template; configure before use")

    def complete(self, system, messages, tools):  # pragma: no cover
        raise NotImplementedError


def build_provider(spec: str) -> Provider:
    """spec = 'openai:gpt-4o' | 'anthropic:claude-...' | 'hf:org/model'."""
    kind, _, model = spec.partition(":")
    if kind == "openai":
        return OpenAICompatibleProvider(model)
    if kind == "anthropic":
        return AnthropicProvider(model)
    if kind == "hf":
        return HFLocalProvider(model)
    raise ValueError(f"unknown provider spec {spec!r}")
