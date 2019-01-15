# -*- coding: utf-8 -*-

import os
from codecs import open

from setuptools import setup

here = os.path.abspath(os.path.dirname(__file__))

about = {}
with open(os.path.join(here, "olm", "__version__.py"), "r", "utf-8") as f:
    exec(f.read(), about)

setup(
    name=about["__title__"],
    version=about["__version__"],
    description=about["__description__"],
    author=about["__author__"],
    author_email=about["__author_email__"],
    url=about["__url__"],
    license=about["__license__"],
    packages=["olm"],
    setup_requires=["cffi>=1.0.0"],
    cffi_modules=["olm_build.py:ffibuilder"],
    install_requires=[
        "cffi>=1.0.0",
        "future",
        "typing;python_version<'3.5'"
    ],
    zip_safe=False
)
