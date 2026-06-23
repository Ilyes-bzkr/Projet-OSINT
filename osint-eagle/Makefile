.PHONY: install run test clean

install:
	pip install -r requirements.txt
	bash scripts/install_playwright.sh

run:
	python main.py

test:
	pytest tests/ -v

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -name "*.pyc" -delete
	rm -f data/osint_eagle.db
