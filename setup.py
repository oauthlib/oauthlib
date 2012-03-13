from os.path import dirname, join
from setuptools import setup, find_packages


def fread(fn):
    with open(join(dirname(__file__), fn), 'r') as f:
        return f.read()

setup(
    name = 'oauthlib',
    version = '0.0.1',
    description = 'Python implementation of OAuth 1.0a',
    long_description = fread('README.rst'),
    author = '',
    author_email = '',
    url = 'https://github.com/idangazit/oauthlib',
    license = fread('LICENSE'),
    packages = find_packages(exclude=('tests', 'docs')),
)

