PYTHON   ?= python

all: olm

olm:
	$(PYTHON) setup.py build

install: olm
	$(PYTHON) setup.py install --skip-build -O1 --root=$(DESTDIR)

test: develop py2develop
	python3 -m pytest
	python2 -m pytest
	python3 -m pytest --flake8 --benchmark-disable
	python3 -m pytest --isort --benchmark-disable
	python3 -m pytest --cov --cov-branch --benchmark-disable

typecheck:
	mypy -p olm --ignore-missing-imports --warn-redundant-casts

clean:
	-rm -r python_olm.egg-info/ dist/ __pycache__/
	-rm *.so _libolm.o
	-rm -r packages/
	-rm -r build/

develop: _libolm.o
py2develop: _libolm.so

_libolm.so: include/olm/olm.h olm_build.py
	python2 olm_build.py
	-rm _libolm.c

_libolm.o: include/olm/olm.h olm_build.py
	python3 olm_build.py
	-rm _libolm.c

archpkg:
	-rm -r packages
	umask 0022 && $(PYTHON) setup.py sdist --dist-dir packages
	cp contrib/archlinux/pkgbuild/PKGBUILD packages
	cd packages && makepkg -i

.PHONY: all olm install clean test archpkg develop
