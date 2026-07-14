#!/usr/bin/env python3
# Hack because logging + setuptools sucks.
import contextlib
with contextlib.suppress(ImportError):
    import multiprocessing


from os.path import dirname, join

from setuptools import find_packages, setup

import oauthlib


def fread(fn):
    with open(join(dirname(__file__), fn), 'r') as f:
        return f.read()


rsa_require = ['cryptography>=3.0.0']
signedtoken_require = ['cryptography>=3.0.0', 'pyjwt>=2.0.0,<3']
signals_require = ['blinker>=1.4.0']

setup(
    name='oauthlib',
    version=oauthlib.__version__,
    description='A generic, spec-compliant, thorough implementation of the OAuth request-signing logic',
    long_description=fread('README.rst'),
    long_description_content_type='text/x-rst',
    author='The OAuthlib Community',
    maintainer='Jonathan Huot',
    maintainer_email='jonathan.huot@gmail.com',
    platforms='any',
    license='BSD-3-Clause',
    packages=find_packages(exclude=('docs', 'examples', 'tests', 'tests.*')),
    python_requires='>=3.9',
    extras_require={
        'rsa': rsa_require,
        'signedtoken': signedtoken_require,
        'signals': signals_require,
    },
    url='https://github.com/oauthlib/oauthlib',
    project_urls={
        'Changelog': 'https://github.com/oauthlib/oauthlib/blob/master/CHANGELOG.rst',
        'Documentation': 'https://oauthlib.readthedocs.io/',
        'Gitter': 'https://gitter.im/oauthlib/Lobby',
        'Issues': 'https://github.com/oauthlib/oauthlib/issues',
        'Source': 'https://github.com/oauthlib/oauthlib',
        'Sponsor': 'https://github.com/sponsors/JonathanHuot',
    },
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'Operating System :: MacOS',
        'Operating System :: POSIX',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: 3.13',
        'Programming Language :: Python :: 3.14',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: Implementation',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ]
)
