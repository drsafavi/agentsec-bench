.PHONY: test generate run reproduce build
test:
	PYTHONPATH=src python3 -m pytest -q
generate:
	PYTHONPATH=src python3 -m agentsec_bench.generate --out data/tasks
run:
	PYTHONPATH=src python3 -m agentsec_bench.cli run --agent all --out results
reproduce:
	bash scripts/reproduce.sh
build:
	python3 -m build
