PYTHON   ?= python

all: olm

olm:
	$(PYTHON) setup.py build

install: olm
	$(PYTHON) setup.py install --skip-build -O1 --root=$(DESTDIR)

test: develop
	$(PYTHON) -m pytest
	$(PYTHON) -m pytest --flake8
	$(PYTHON) -m pytest --isort

clean:
	-rm -r python_olm.egg-info/ dist/ __pycache__/
	-rm *.so _libolm.o
	-rm -r packages/
	-rm -r build/

develop: _libolm.o

_libolm.o:
	python3 olm_build.py
	-rm _libolm.c

archpkg:
	$(PYTHON) setup.py sdist --dist-dir packages
	cp contrib/archlinux/pkgbuild/PKGBUILD packages
	cd packages && makepkg

.PHONY: all olm install clean test archpkg develop
