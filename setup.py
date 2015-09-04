#!/usr/bin/env python

from setuptools import setup

setup(name='ffx',
      install_requires=['gmpy','pycrypto'],
      test_suite = 'ffx.tests',
      version='0.0.1',
      description='FFX',
      author='Kevin P. Dyer',
      author_email='kpdyer@gmail.com',
      url='https://github.com/kpdyer/libffx',
      packages=['ffx'],
      )
