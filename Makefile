.PHONY: install test lint typecheck benchmark clean dataset train

install:
	pip install --upgrade pip
	pip install -e ".[all,dev]"

test:
	pytest -v --tb=short tests/

lint:
	ruff check src/ tests/

typecheck:
	mypy src/opencryptodetect

dataset:
	ocd ml prepare-dataset

train:
	ocd ml train

benchmark:
	ocd benchmark

check: lint test

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache .coverage

