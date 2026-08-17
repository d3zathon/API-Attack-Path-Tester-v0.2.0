.PHONY: install test demo lab-start lab-stop clean

install:
	python3 -m venv .venv
	. .venv/bin/activate && python -m pip install -e '.[test]'

test:
	python -m pytest

demo:
	. .venv/bin/activate && apiat demo

lab-start:
	. .venv/bin/activate && apiat lab start

lab-stop:
	. .venv/bin/activate && apiat lab stop

clean:
	rm -rf .pytest_cache .venv build dist src/*.egg-info src/apiat.egg-info
