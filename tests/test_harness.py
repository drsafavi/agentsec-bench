from agentsec_bench.agents.reference import GuardedAgent, KeywordFilterAgent, NaiveAgent
from agentsec_bench.generate import generate
from agentsec_bench.harness import run_suite, run_task
from agentsec_bench.scorer import summarise

TASKS = generate()


def _overall(agent):
    return summarise(run_suite(TASKS, agent))["overall"]


def test_benign_baseline_all_agents():
    for agent in (NaiveAgent(), KeywordFilterAgent(), GuardedAgent()):
        o = _overall(agent)
        assert o["benign_task_success"] == 1.0, agent.name


def test_naive_fully_compromised():
    o = _overall(NaiveAgent())
    assert o["attack_success"] == 1.0
    assert o["targeted_harm"] == 1.0
    assert o["utility_under_attack"] == 0.0


def test_guarded_defends():
    o = _overall(GuardedAgent())
    assert o["attack_success"] == 0.0
    assert o["targeted_harm"] == 0.0
    assert o["utility_under_attack"] == 1.0


def test_keyword_filter_blocks_plain_only():
    rows = run_suite(TASKS, KeywordFilterAgent())
    by = summarise(rows)["by"]["obfuscation"]
    assert by["plain"]["attack_success"] == 0.0
    assert by["encoded"]["attack_success"] == 1.0
    assert by["split"]["attack_success"] > 0.5


def test_no_payload_leakage_in_benign_condition():
    # With no payload present, even the naive agent must never perform the
    # attack: this proves the attack is driven only by injected tool output,
    # not by the benign fixtures or the user prompt.
    from agentsec_bench.checks import evaluate
    from agentsec_bench.harness import run_stage
    agent = NaiveAgent()
    for t in TASKS:
        _, benign_trace = run_stage(t, agent, t["benign_actions"], t.get("naive_actions", []),
                                    fragments=None, answer=t.get("benign_answer", "Done."))
        assert benign_trace["complied"] is False, t["task_id"]
        assert not evaluate(t["attack_success"], benign_trace), t["task_id"]


def test_result_schema():
    r = run_task(TASKS[0], NaiveAgent())
    for k in ("task_id", "environment", "attack_class", "obfuscation", "agent",
              "benign_task_success", "attack_success", "targeted_harm", "utility_under_attack"):
        assert k in r
