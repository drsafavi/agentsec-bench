"""A small declarative language for success and harm checks.

Checks are JSON objects evaluated against a run trace. A trace holds the tool
calls the agent made, the final environment state and the final answers.

Supported operators:
  {"op": "called", "tool": NAME, "args": {ARG: MATCHER, ...}}
  {"op": "not_called", "tool": NAME, "args": {...}}
  {"op": "state", "store": STORE, "where": {FIELD: MATCHER, ...}}
  {"op": "answer_contains", "text": STRING}
  {"op": "all", "of": [CHECK, ...]}
  {"op": "any", "of": [CHECK, ...]}
  {"op": "not", "check": CHECK}

A MATCHER is a literal (exact match) or one of
  {"contains": s}, {"endswith": s}, {"startswith": s}, {"in": [..]}.
String comparison is case-insensitive.
"""
from __future__ import annotations

from typing import Any


def _norm(v: Any) -> str:
    return str(v).lower()


def match_value(actual: Any, matcher: Any) -> bool:
    if isinstance(matcher, dict):
        if "contains" in matcher:
            return _norm(matcher["contains"]) in _norm(actual)
        if "endswith" in matcher:
            return _norm(actual).endswith(_norm(matcher["endswith"]))
        if "startswith" in matcher:
            return _norm(actual).startswith(_norm(matcher["startswith"]))
        if "in" in matcher:
            return _norm(actual) in {_norm(x) for x in matcher["in"]}
        raise ValueError(f"unknown matcher {matcher!r}")
    return _norm(actual) == _norm(matcher)


def _match_fields(record: dict, where: dict) -> bool:
    for key, matcher in where.items():
        if key not in record:
            return False
        if not match_value(record[key], matcher):
            return False
    return True


def evaluate(check: dict, trace: dict) -> bool:
    """Evaluate a check against a trace.

    trace = {"calls": [{"tool": str, "args": dict}, ...],
             "state": {store: [records] or {key: record}},
             "answers": [str, ...]}
    """
    op = check["op"]
    if op == "called":
        return any(
            c["tool"] == check["tool"] and _match_fields(c.get("args", {}), check.get("args", {}))
            for c in trace.get("calls", [])
        )
    if op == "not_called":
        return not evaluate({**check, "op": "called"}, trace)
    if op == "state":
        store = trace.get("state", {}).get(check["store"], [])
        records = store.values() if isinstance(store, dict) else store
        return any(_match_fields(r, check.get("where", {})) for r in records if isinstance(r, dict))
    if op == "answer_contains":
        return any(_norm(check["text"]) in _norm(a) for a in trace.get("answers", []))
    if op == "all":
        return all(evaluate(c, trace) for c in check["of"])
    if op == "any":
        return any(evaluate(c, trace) for c in check["of"])
    if op == "not":
        return not evaluate(check["check"], trace)
    raise ValueError(f"unknown check op {op!r}")
