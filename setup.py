#!/usr/bin/env python

from distutils.core import setup
from Cython.Build import cythonize

setup(name='FFX',
extra_build_args=['-O3'],
 ext_modules = cythonize("FFX/__init__.pyx"),
      )
