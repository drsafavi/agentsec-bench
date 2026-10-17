# Contributing

- Run the tests with `make test` (or `PYTHONPATH=src pytest -q`).
- Rebuild the task suite with `make generate`; the suite checksum in
  `data/tasks/CHECKSUMS.txt` must stay stable unless a task change is intended.
- New environments go in `src/agentsec_bench/environments/`; add tools as
  `tool_<name>` methods with a `PARAMS` entry and a docstring.
- New attack classes or obfuscation levels must keep the three factors
  (environment, attack class, obfuscation) independent and the marginal counts
  balanced; see `tests/test_generate.py`.
- Every success or harm check must be expressed in the declarative check
  language so it can be verified without running a model.
- Keep all task data synthetic and all attacker destinations on the `.example`
  domain.
