"""Agent interface and reference agents.

An agent implements ``decide_follow(level, directive_present)`` and the harness
drives perception and action. Three reference agents ship with the benchmark so
that the harness can be validated without any language model:

  NaiveAgent         follows any directive it can read in a tool output
  KeywordFilterAgent a weak defence: blocks plain-text directives only
  GuardedAgent       a provenance / spotlighting defence: never follows
                     instructions found in tool output

Real language-model agents are added by implementing ``ModelAgent`` against the
provider adapter (see agentsec_bench.agents.model).
"""
from .reference import Agent, GuardedAgent, KeywordFilterAgent, NaiveAgent, REFERENCE_AGENTS

__all__ = ["Agent", "NaiveAgent", "KeywordFilterAgent", "GuardedAgent", "REFERENCE_AGENTS"]
