"""AgentSec-Bench: an open benchmark for indirect prompt injection in tool-augmented agents.

The package provides deterministic tool environments, a payload library, a
provider-agnostic agent interface, an execution harness and a scorer. It does
not ship results: results are produced only when a user runs the harness.
"""

__version__ = "0.1.0"

ENVIRONMENTS = ("email", "calendar", "filesystem", "web", "code", "ehr")
ATTACK_CLASSES = (
    "goal_hijacking",
    "data_exfiltration",
    "unauthorised_tool_invocation",
    "privilege_escalation_chaining",
    "memory_poisoning",
    "multi_agent_relay",
)
OBFUSCATION_LEVELS = ("plain", "encoded", "split")
ATTACKER_DOMAIN = "attacker.example"
