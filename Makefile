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

docker: Dockerfile samlkeygen/*.py
	docker build -t samlkeygen:$(VERSION) .
	touch docker

tag: docker
	docker tag samlkeygen:$(VERSION) samlkeygen:latest
	touch tag

push: tag
	docker tag samlkeygen:$(VERSION) turnerlabs/samlkeygen:$(VERSION)
	docker tag samlkeygen:latest turnerlabs/samlkeygen:latest
	docker push turnerlabs/samlkeygen:$(VERSION)
	docker push turnerlabs/samlkeygen:latest
	touch push
