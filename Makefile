.PHONY: test lint fmt typecheck install clean

install:
	uv sync --all-extras

test:
	uv run pytest tests/ -v --tb=short

coverage:
	uv run coverage run -m pytest tests/ -v --tb=short
	uv run coverage report -m

lint:
	uv run ruff check src/ tests/

fmt:
	uv run ruff format src/ tests/
	uv run ruff check --fix src/ tests/

typecheck:
	uv run mypy src/signet/

clean:
	rm -rf build/ dist/ *.egg-info src/*.egg-info .mypy_cache .pytest_cache .ruff_cache .coverage htmlcov/
