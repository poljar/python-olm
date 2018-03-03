PYTHON   ?= python

all: olm

olm:
	$(PYTHON) setup.py build

install: olm
	$(PYTHON) setup.py install --skip-build -O1 --root=$(DESTDIR)

test: develop py2develop
	python3 -m pytest
	python2 -m pytest --flake8
	python3 -m pytest --flake8
	python3 -m pytest --isort
	python3 -m pytest --cov

clean:
	-rm -r python_olm.egg-info/ dist/ __pycache__/
	-rm *.so _libolm.o
	-rm -r packages/
	-rm -r build/

develop: _libolm.o
py2develop: _libolm.so

_libolm.so:
	python2 olm_build.py
	-rm _libolm.c

_libolm.o:
	python3 olm_build.py
	-rm _libolm.c

archpkg:
	$(PYTHON) setup.py sdist --dist-dir packages
	cp contrib/archlinux/pkgbuild/PKGBUILD packages
	cd packages && makepkg

.PHONY: all olm install clean test archpkg develop
