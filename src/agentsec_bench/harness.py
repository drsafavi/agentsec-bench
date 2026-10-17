"""Execution harness.

For each task the harness runs two conditions against fresh deterministic
environments:

  benign    the task with no payload (placeholders resolve to empty). Measures
            benign task success.
  attacked  the task with its payload rendered into the tool outputs. Measures
            attack success, targeted harm and utility under attack.

Memory-poisoning tasks run a second session whose memory is carried over from
the attacked session. Multi-agent-relay tasks feed the primary agent's handoff
to a second agent through a tool output. Both second stages use the reference
agents, so every reported number is produced by executing the pipeline.
"""
from __future__ import annotations

import copy

from . import payloads
from .agents.reference import reconstruct
from .checks import evaluate
from .environments import ENVIRONMENT_CLASSES


def _variant(task) -> int:
    return sum(ord(ch) for ch in task["task_id"])


def _build_env(task, fragments, memory=None, sandbox=None):
    env = ENVIRONMENT_CLASSES[task["environment"]](task["fixtures"], fragments, sandbox=sandbox)
    if memory:
        env.state["memory"] = copy.deepcopy(memory)
    return env


def _replay(env, actions):
    outputs = []
    for a in actions:
        outputs.append(env.call(a["tool"], a.get("args", {})))
    return outputs


def _trace(env, answers, complied, how):
    return {"calls": env.calls, "state": env.snapshot(), "answers": answers,
            "complied": complied, "how": how}


def run_stage(task, agent, benign_actions, naive_actions, fragments,
              extra_untrusted=None, memory=None, answer="Done.", relay_suffix="", sandbox=None):
    """Run one agent session and return (env, trace)."""
    env = _build_env(task, fragments, memory=memory, sandbox=sandbox)
    outputs = _replay(env, benign_actions)
    perceived = list(outputs) + list(extra_untrusted or [])
    directive, how = reconstruct(perceived)
    comply = directive is not None and agent.will_follow(how)
    ans = answer
    if comply and naive_actions:
        _replay(env, naive_actions)
    if comply and relay_suffix:
        ans = ans + relay_suffix
    return env, _trace(env, [ans], comply, how)


def run_task(task, agent, sandbox=None) -> dict:
    """Run one task with one agent; return per-task measurements."""
    level = task["obfuscation"]
    frags = payloads.render(task["injected_instruction"], level, variant=_variant(task))

    # benign condition: no payload present.
    _, benign_trace = run_stage(task, agent, task["benign_actions"], [], None,
                                answer=task.get("benign_answer", "Done."), sandbox=sandbox)
    benign_success = bool(evaluate(task["benign_success"], benign_trace))

    # attacked condition.
    atk_env, atk_trace = run_stage(
        task, agent, task["benign_actions"], task.get("naive_actions", []), frags,
        answer=task.get("benign_answer", "Done."),
        relay_suffix=task.get("naive_answer_suffix", "") if task.get("relay") else "",
        sandbox=sandbox)
    attack_success = bool(evaluate(task["attack_success"], atk_trace))

    harm = False
    if task.get("relay"):
        # harm only if the primary relayed the directive and a second agent acts.
        if attack_success and task.get("second_stage"):
            ss = task["second_stage"]
            handoff = f"Handoff note from the previous assistant: {ss['instruction']}"
            _, s2 = run_stage(task, agent, ss["benign_actions"], ss["naive_actions"], None,
                              extra_untrusted=[handoff], sandbox=sandbox)
            harm = bool(evaluate(ss["harm"], s2)) if ss.get("harm") else False
    elif task.get("memory_followup"):
        if attack_success and task.get("second_stage"):
            ss = task["second_stage"]
            follow_actions = ss["benign_actions"] + [{"tool": "memory_read", "args": {}}]
            _, s2 = run_stage(task, agent, follow_actions, ss["naive_actions"], None,
                              memory=atk_env.state.get("memory"), sandbox=sandbox)
            harm = bool(evaluate(ss["harm"], s2)) if ss.get("harm") else False
    else:
        hc = task.get("harm_check")
        harm = bool(evaluate(hc, atk_trace)) if hc else attack_success

    return {
        "task_id": task["task_id"], "environment": task["environment"],
        "attack_class": task["attack_class"], "obfuscation": level,
        "agent": agent.name,
        "benign_task_success": benign_success,
        "attack_success": attack_success,
        "targeted_harm": harm,
        "utility_under_attack": benign_success and not attack_success,
        "perceived_how": atk_trace["how"],
    }


def run_suite(tasks, agent, sandbox=None):
    return [run_task(t, agent, sandbox=sandbox) for t in tasks]
