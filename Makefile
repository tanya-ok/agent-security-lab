.PHONY: doctor prepare up demo status report down check

doctor prepare up demo status report down:
	./lab $@

check:
	uv run --locked python -m unittest discover -s tests -v
	uv run --locked ruff check src tests tools lab
	uv run --locked ruff format --check src tests tools lab
	node --check web/app.js
	node --check web/runtime.js
	node --test tests/test_credentials.mjs

.PHONY: docs-check
docs-check:
	uv run --locked --group docs zensical build --strict --clean

.PHONY: publication-check
publication-check:
	python3 tools/publication.py
