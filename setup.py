# -*- coding: utf-8 -*-

import os

from os.path import dirname, join
from setuptools import setup, find_packages, Command

# Hack because logging + setuptools sucks.
import multiprocessing


def fread(fn):
    with open(join(dirname(__file__), fn), 'r') as f:
        return f.read()

tests_require = ['nose', 'unittest2', 'pycrypto']

requires = ['pycrypto']

setup(
    name='oauthlib',
    version='0.1.1',
    description='A generic, spec-compliant, thorough implementation of the OAuth request-signing logic',
    long_description=fread('README.rst'),
    author='Idan Gazit',
    author_email='idan@gazit.me',
    url='https://github.com/idangazit/oauthlib',
    license=fread('LICENSE'),
    packages=find_packages(exclude=('tests', 'docs')),
    test_suite='nose.collector',
    tests_require=tests_require,
    extras_require={'test': tests_require},
)
