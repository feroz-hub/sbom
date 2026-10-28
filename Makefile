PYTHON ?= .venv/bin/python

.PHONY: greenfield-setup greenfield-start greenfield-restart greenfield-schema greenfield-integrity greenfield-api greenfield-https
greenfield-https:
	$(PYTHON) -B -m scripts.greenfield_https verify-served

greenfield-setup:
	$(PYTHON) -B -m scripts.greenfield_uuid setup

greenfield-start:
	$(PYTHON) -B -m scripts.greenfield_uuid start

greenfield-restart:
	$(PYTHON) -B -m scripts.greenfield_uuid restart

greenfield-schema:
	$(PYTHON) -B -m scripts.greenfield_schema_check

greenfield-integrity:
	$(PYTHON) -B -m scripts.greenfield_integrity

greenfield-api:
	$(PYTHON) -B -m scripts.greenfield_acceptance
