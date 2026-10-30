PYTHON ?= .venv/bin/python

.PHONY: greenfield-schema greenfield-integrity greenfield-api
greenfield-schema:
	$(PYTHON) -B -m scripts.greenfield_schema_check

greenfield-integrity:
	$(PYTHON) -B -m scripts.greenfield_integrity

greenfield-api:
	$(PYTHON) -B -m scripts.greenfield_acceptance
