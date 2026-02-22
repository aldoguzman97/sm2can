.PHONY: install dev test lint build clean publish probe

install:
	pip install .

dev:
	pip install -e ".[dev]"

test:
	pytest --tb=short -q

lint:
	ruff check sm2can/

build:
	python -m build

clean:
	rm -rf dist/ build/ *.egg-info .pytest_cache .ruff_cache
	find . -name __pycache__ -type d -exec rm -rf {} +

publish: build
	python -m twine upload dist/*

probe:
	sudo python -m sm2can.tools.probe

capture-guide:
	python -m sm2can.tools.capture_decoder guide
