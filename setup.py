# -*- coding: utf-8 -*-

# Hack because logging + setuptools sucks.
try:
    import multiprocessing
except ImportError:
    pass

import sys
from os.path import dirname, join

from setuptools import find_packages, setup

import oauthlib


def fread(fn):
    with open(join(dirname(__file__), fn), 'r') as f:
        return f.read()

if sys.version_info[0] == 3:
    tests_require = ['nose', 'cryptography', 'pyjwt>=1.0.0', 'blinker']
else:
    tests_require = ['nose', 'unittest2', 'cryptography', 'mock>=2.0', 'pyjwt>=1.0.0', 'blinker']
rsa_require = ['cryptography']
signedtoken_require = ['cryptography', 'pyjwt>=1.0.0']
signals_require = ['blinker']

requires = []

setup(
    name='oauthlib',
    version=oauthlib.__version__,
    description='A generic, spec-compliant, thorough implementation of the OAuth request-signing logic',
    long_description=fread('README.rst'),
    author='The OAuthlib Community',
    author_email='idan@gazit.me',
    maintainer='Ib Lundgren',
    maintainer_email='ib.lundgren@gmail.com',
    url='https://github.com/oauthlib/oauthlib',
    platforms='any',
    license='BSD',
    packages=find_packages(exclude=('docs', 'tests', 'tests.*')),
    test_suite='nose.collector',
    tests_require=tests_require,
    extras_require={
        'test': tests_require,
        'rsa': rsa_require,
        'signedtoken': signedtoken_require,
        'signals': signals_require,
    },
    install_requires=requires,
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved',
        'License :: OSI Approved :: BSD License',
        'Operating System :: MacOS',
        'Operating System :: POSIX',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: Implementation',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ]
)
