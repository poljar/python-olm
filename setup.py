# -*- coding: utf-8 -*-

from setuptools import setup

setup(
    name="python-olm",
    version="2.2",
    url="https://git.matrix.org/git/olm/",
    author='Damir Jelić',
    author_email="poljar@termina.org.uk",
    description=("python CFFI bindings for the olm "
                 "cryptographic ratchet library"),
    license="Apache License 2.0",
    packages=["olm"],
    setup_requires=["cffi>=1.0.0"],
    cffi_modules=["olm_build.py:ffibuilder"],
    install_requires=["cffi>=1.0.0"],
    zip_safe=False
)
