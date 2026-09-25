"""Test-suite configuration.

Most tests are ``unittest`` classes built on
``tests.unittest.TestCase`` (an ``IsolatedAsyncioTestCase``). This hook runs
plain pytest-style ``async def test_*`` functions on a fresh event loop,
so no third-party asyncio plugin is required.
"""
import asyncio
import inspect
import unittest

import pytest


@pytest.hookimpl(tryfirst=True)
def pytest_pyfunc_call(pyfuncitem):
    if not inspect.iscoroutinefunction(pyfuncitem.obj):
        return None
    funcargs = pyfuncitem.funcargs
    testargs = {arg: funcargs[arg] for arg in pyfuncitem._fixtureinfo.argnames}
    asyncio.run(pyfuncitem.obj(**testargs))
    return True


def pytest_collection_modifyitems(session, config, items):
    """Fail loudly if an ``async def`` test would silently never run.

    ``unittest.TestCase`` (unlike ``IsolatedAsyncioTestCase``) calls an async
    test method, gets a coroutine back, discards it and reports a pass.
    """
    offenders = set()
    for item in items:
        cls = getattr(item, 'cls', None)
        if cls is None or not issubclass(cls, unittest.TestCase):
            continue
        if issubclass(cls, unittest.IsolatedAsyncioTestCase):
            continue
        if inspect.iscoroutinefunction(getattr(cls, item.name.split('[')[0], None)):
            offenders.add('{}.{}'.format(cls.__module__, cls.__qualname__))
    if offenders:
        raise pytest.UsageError(
            'async test methods on non-async TestCase classes (use '
            'tests.unittest.TestCase): ' + ', '.join(sorted(offenders)))
