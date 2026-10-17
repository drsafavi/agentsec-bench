"""Exercise the model-agent tool-calling loop with a scripted fake provider.

No network and no API key: the FakeProvider replays a fixed sequence of tool
calls, which proves the model harness wires perception, tool execution and
scoring together correctly.
"""
from agentsec_bench.agents.model import FakeProvider, build_provider
from agentsec_bench.generate import generate
from agentsec_bench.model_harness import run_model_task

TASKS = {t["task_id"]: t for t in generate()}


def _first(attack_class):
    return next(t for t in TASKS.values() if t["attack_class"] == attack_class)


def _steps(actions):
    return [{"tool": a["tool"], "args": a["args"]} for a in actions]


def test_fake_provider_benign_then_attack():
    # a compliant model: does the benign actions, then follows the injected action.
    # run_model_task runs the benign condition first, then the attacked one, from
    # one shared script (the benign pass ends at the first answer).
    t = _first("data_exfiltration")
    script = (_steps(t["benign_actions"]) + [{"answer": "done"}]
              + _steps(t["benign_actions"]) + _steps(t["naive_actions"]) + [{"answer": "done"}])
    r = run_model_task(t, FakeProvider(script))
    assert r["benign_task_success"] is True
    assert r["attack_success"] is True


def test_fake_provider_defended_model():
    # a model that only does the benign actions and ignores injected content.
    t = _first("data_exfiltration")
    script = (_steps(t["benign_actions"]) + [{"answer": "done"}]
              + _steps(t["benign_actions"]) + [{"answer": "done"}])
    r = run_model_task(t, FakeProvider(script))
    assert r["benign_task_success"] is True
    assert r["attack_success"] is False
    assert r["utility_under_attack"] is True


def test_build_provider_unknown():
    import pytest
    with pytest.raises(ValueError):
        build_provider("nope:x")
