PYTHON=python2
PIP=pip2
VERSION=$(shell $(PYTHON) -msamlkeygen._version)

dist/samlkeygen-$(VERSION): *.py README.rst
	$(PYTHON) setup.py sdist

README.rst: README.md
	pandoc --from=markdown --to=rst --output=$@ $<

clean: 
	rm -rf dist samlkeygen.egg-info *.pyc */*.pyc README.rst

test:
	bash ./run-tests.sh

docker:
	docker build -t samlkeygen:$(VERSION) .

tag: docker
	docker tag samlkeygen:$(VERSION) samlkeygen:latest

push: tag
	docker push samlkeygen:$(VERSION) turnerlabs/samlkeygen:$(VERSION)
	docker tag turnerlabs/samlkeygen:$(VERSION) turnerlabs/samlkeygen:latest
