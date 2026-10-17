"""Command-line entry point.

  python -m agentsec_bench.cli run --agent naive --out results/
  python -m agentsec_bench.cli run --agent all --tasks data/tasks --out results/

Loads tasks from a directory of task JSON files (or regenerates them in
memory), runs the chosen reference agent(s) through the harness and writes the
per-task results and the summary. Reference agents need no API key. A model
agent is selected with --agent model:<provider>:<name> once the adapter is
configured (see agents/model.py).
"""
from __future__ import annotations

import argparse
import glob
import json
import os

from .agents.reference import REFERENCE_AGENTS
from .generate import generate
from .harness import run_suite
from .scorer import write_results


def load_tasks(path):
    if path and os.path.isdir(path):
        files = sorted(f for f in glob.glob(os.path.join(path, "*.json"))
                       if os.path.basename(f) not in ("index.json",))
        tasks = [json.load(open(f)) for f in files]
        tasks = [t for t in tasks if "task_id" in t and "injected_instruction" in t]
        if tasks:
            return tasks
    return generate()


def main(argv=None):
    ap = argparse.ArgumentParser(prog="agentsec-bench")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run the benchmark")
    r.add_argument("--agent", default="all", help="naive | keyword_filter | guarded | all")
    r.add_argument("--tasks", default="data/tasks", help="task directory (regenerated if missing)")
    r.add_argument("--out", default="results", help="output directory")
    r.add_argument("--sandbox", default="none", choices=["none", "docker"])
    args = ap.parse_args(argv)

    tasks = load_tasks(args.tasks)
    os.makedirs(args.out, exist_ok=True)
    sandbox = None
    if args.sandbox == "docker":
        from .sandbox import DockerSandbox
        sandbox = DockerSandbox()

    names = list(REFERENCE_AGENTS) if args.agent == "all" else [args.agent]
    index = {}
    for name in names:
        if name not in REFERENCE_AGENTS:
            raise SystemExit(f"unknown agent {name}; choose from {list(REFERENCE_AGENTS)} or 'all'")
        agent = REFERENCE_AGENTS[name]()
        rows = run_suite(tasks, agent, sandbox=sandbox)
        summary = write_results(
            rows,
            os.path.join(args.out, f"results_{name}.csv"),
            os.path.join(args.out, f"results_{name}.json"),
            os.path.join(args.out, f"summary_{name}.json"))
        index[name] = summary["overall"]
        o = summary["overall"]
        print(f"[{name}] n={summary['n']} benign={o['benign_task_success']:.3f} "
              f"ASR={o['attack_success']:.3f} harm={o['targeted_harm']:.3f} "
              f"utility={o['utility_under_attack']:.3f}")
    with open(os.path.join(args.out, "index.json"), "w") as fh:
        json.dump(index, fh, indent=2)


if __name__ == "__main__":
    main()
