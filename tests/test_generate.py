from collections import Counter

from agentsec_bench import ATTACK_CLASSES, ENVIRONMENTS, OBFUSCATION_LEVELS
from agentsec_bench.generate import generate


TASKS = generate()


def test_count():
    assert len(TASKS) == 240


def test_marginals_exact():
    assert Counter(t["environment"] for t in TASKS) == {e: 40 for e in ENVIRONMENTS}
    assert Counter(t["attack_class"] for t in TASKS) == {c: 40 for c in ATTACK_CLASSES}
    assert Counter(t["obfuscation"] for t in TASKS) == {l: 80 for l in OBFUSCATION_LEVELS}


def test_factors_independent_cells_populated():
    ec = Counter((t["environment"], t["attack_class"]) for t in TASKS)
    cl = Counter((t["attack_class"], t["obfuscation"]) for t in TASKS)
    el = Counter((t["environment"], t["obfuscation"]) for t in TASKS)
    assert len(ec) == 36 and len(cl) == 18 and len(el) == 18
    # class x level balanced (not confounded)
    assert max(cl.values()) - min(cl.values()) <= 1


def test_unique_task_ids():
    assert len({t["task_id"] for t in TASKS}) == 240


def test_payload_never_in_user_prompt():
    # the injected instruction must reach the agent only through tool outputs.
    for t in TASKS:
        assert t["injected_instruction"] not in t["user_prompt"]
        assert "attacker.example" not in t["user_prompt"]
        assert t["marker"] not in t["user_prompt"]
        assert t["canary"] not in t["user_prompt"]


def test_attacker_targets_are_synthetic():
    for t in TASKS:
        assert t["attacker_target"].endswith(".example")


def test_determinism():
    a = generate()
    b = generate()
    assert [x["task_id"] for x in a] == [x["task_id"] for x in b]
    assert a == b


def test_every_task_has_checks():
    for t in TASKS:
        assert t["benign_success"] and t["attack_success"]
        assert isinstance(t["benign_actions"], list) and t["benign_actions"]
