# -*- coding: utf-8 -*-

import os
import sys

from os.path import dirname, join
from setuptools import setup, find_packages, Command

# Hack because logging + setuptools sucks.
import multiprocessing


def fread(fn):
    with open(join(dirname(__file__), fn), 'r') as f:
        return f.read()

if sys.version_info[0] == 3:
    tests_require = ['nose', 'pycrypto']
else:
    tests_require = ['nose', 'unittest2', 'pycrypto', 'mock']
rsa_require = ['pycrypto']

requires = []

setup(
    name='oauthlib',
    version='0.3.3',
    description='A generic, spec-compliant, thorough implementation of the OAuth request-signing logic',
    long_description=fread('README.rst'),
    author='Idan Gazit',
    author_email='idan@gazit.me',
    url='https://github.com/idan/oauthlib',
    license=fread('LICENSE'),
    packages=find_packages(exclude=('docs','tests','tests.*')),
    test_suite='nose.collector',
    tests_require=tests_require,
    extras_require={'test': tests_require, 'rsa': rsa_require},
    install_requires=requires,
)
