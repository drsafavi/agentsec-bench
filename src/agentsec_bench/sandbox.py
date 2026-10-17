"""Optional Docker sandbox for the code-execution and file-system environments.

By default the harness uses deterministic mock tools and never executes agent
commands. With ``--sandbox docker`` the code environment's ``run_command``
tool runs inside a throwaway container with no network access, a read-only
root file system and a small memory and time limit.
"""
from __future__ import annotations

import shutil
import subprocess


class DockerSandbox:
    def __init__(self, image: str = "python:3.11-slim", timeout: int = 20, memory: str = "256m"):
        if not shutil.which("docker"):
            raise RuntimeError("docker is not installed; run without --sandbox docker to use mock tools")
        self.image, self.timeout, self.memory = image, timeout, memory
        self.events: list[tuple[str, str]] = []

    def run(self, command: str) -> str:
        self.events.append(("run", command))
        cmd = ["docker", "run", "--rm", "--network", "none", "--read-only", "--tmpfs", "/tmp",
               "--memory", self.memory, "--pids-limit", "64", self.image, "sh", "-c", command]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
            return (p.stdout + p.stderr)[-4000:]
        except subprocess.TimeoutExpired:
            return "(sandbox) command timed out"

    def log(self, kind: str, detail: str) -> None:
        self.events.append((kind, detail))
