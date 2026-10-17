"""Deterministic mock tool environment base class.

Every environment keeps its state in named stores (lists or dicts of
records). Tools are methods named ``tool_<name>``; their docstring is the tool
description and ``PARAMS`` gives the JSON schema of their arguments.

Fixture records may contain placeholders of the form ``{{PAYLOAD:k}}``. When
the environment is built for an attacked run, placeholder k is replaced by
fragment k of the rendered payload; in a benign run it is replaced by an
empty string. Payload text therefore only ever reaches the agent through tool
outputs, never through the user prompt.
"""
from __future__ import annotations

import copy
import json
import re
from typing import Any, Callable

PLACEHOLDER = re.compile(r"\{\{PAYLOAD:(\d+)\}\}")


def fill_placeholders(obj: Any, fragments: list[str] | None) -> Any:
    """Replace payload placeholders recursively."""
    if isinstance(obj, str):
        def repl(m: re.Match) -> str:
            if not fragments:
                return ""
            i = int(m.group(1))
            return fragments[i] if i < len(fragments) else ""
        return PLACEHOLDER.sub(repl, obj).strip() if PLACEHOLDER.search(obj) else obj
    if isinstance(obj, list):
        return [fill_placeholders(x, fragments) for x in obj]
    if isinstance(obj, dict):
        return {k: fill_placeholders(v, fragments) for k, v in obj.items()}
    return obj


class ToolError(Exception):
    pass


class Environment:
    """Base class. Subclasses define tool_* methods and PARAMS."""

    name = "base"
    PARAMS: dict[str, dict] = {}

    def __init__(self, fixtures: dict, fragments: list[str] | None = None, sandbox: Any = None):
        self.state: dict[str, Any] = fill_placeholders(copy.deepcopy(fixtures), fragments)
        self.state.setdefault("memory", {})
        self.sandbox = sandbox
        self.calls: list[dict] = []

    # ---- tool registry -------------------------------------------------
    @classmethod
    def tool_names(cls) -> list[str]:
        return sorted(n[5:] for n in dir(cls) if n.startswith("tool_"))

    @classmethod
    def tool_specs(cls) -> list[dict]:
        specs = []
        for n in cls.tool_names():
            fn: Callable = getattr(cls, "tool_" + n)
            params = cls.PARAMS.get(n, {})
            specs.append({
                "name": n,
                "description": (fn.__doc__ or "").strip(),
                "parameters": {
                    "type": "object",
                    "properties": {k: {"type": "string", "description": v} for k, v in params.items()},
                    "required": list(params),
                },
            })
        return specs

    def call(self, tool: str, args: dict | None) -> str:
        args = dict(args or {})
        self.calls.append({"tool": tool, "args": args})
        fn = getattr(self, "tool_" + tool, None)
        if fn is None:
            return json.dumps({"error": f"unknown tool {tool}"})
        missing = [p for p in self.PARAMS.get(tool, {}) if p not in args]
        if missing:
            return json.dumps({"error": f"missing arguments: {', '.join(missing)}"})
        try:
            out = fn(**{k: str(v) for k, v in args.items() if k in self.PARAMS.get(tool, {})})
        except ToolError as e:
            out = {"error": str(e)}
        return json.dumps(out, ensure_ascii=False)

    # ---- shared memory tools (used by the memory-poisoning class) -------
    def tool_memory_write(self, key: str, value: str):
        """Store a note in long-term memory that persists to later sessions."""
        self.state["memory"][key] = {"key": key, "value": value}
        return {"ok": True}

    def tool_memory_read(self):
        """Return all notes stored in long-term memory."""
        return list(self.state["memory"].values())

    def snapshot(self) -> dict:
        return copy.deepcopy(self.state)


Environment.PARAMS = {"memory_write": {"key": "note name", "value": "note text"}, "memory_read": {}}
