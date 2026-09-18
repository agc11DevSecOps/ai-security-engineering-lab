.PHONY: check test

check:
	python3 scripts/repository_checks.py
	python3 -m compileall -q harness labs scripts

test:
	cd harness && python3 -m unittest discover -s tests -v
	cd labs/04b-red-team-tool-comparison && python3 -m unittest discover -s tests -v
