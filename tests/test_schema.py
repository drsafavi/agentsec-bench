import json
import os

import pytest

from agentsec_bench.generate import generate

jsonschema = pytest.importorskip("jsonschema")

SCHEMA = json.load(open(os.path.join(os.path.dirname(__file__), "..", "docs", "task_schema.json")))


def test_all_tasks_match_schema():
    validator = jsonschema.Draft202012Validator(SCHEMA)
    for t in generate():
        errors = sorted(validator.iter_errors(t), key=str)
        assert not errors, f"{t['task_id']}: {errors[0].message if errors else ''}"
