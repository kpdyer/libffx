#!/usr/bin/env python

from setuptools import setup

setup(
    name='ffx',
    install_requires=['gmpy', 'pycryptodome', 'six'],
    test_suite='ffx.tests',
    version='0.0.2',
    description='FFX',
    author='Kevin P. Dyer',
    author_email='kpdyer@gmail.com',
    url='https://github.com/kpdyer/libffx',
    packages=['ffx'],
    classifiers=[
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'Development Status :: 4 - Beta',
        'Topic :: Security :: Cryptography',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
)
