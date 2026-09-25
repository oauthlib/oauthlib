import inspect
import unittest
import urllib.parse as urlparse
from unittest import mock

from oauthlib.oauth1 import RequestValidator as OAuth1RequestValidator
from oauthlib.openid.connect.core.request_validator import (
    RequestValidator as OIDCRequestValidator,
)


class TestCase(unittest.IsolatedAsyncioTestCase):
    """Base test case: runs both sync and ``async def`` test methods."""

    async def assertRaisesAsync(self, expected_exception, func, *args, **kwargs):  # noqa: N802
        """Async counterpart of ``assertRaises(exc, callable, *args)``.

        ``assertRaises`` with a coroutine function would only create (and
        never run) the coroutine, so the assertion would always fail.
        """
        with self.assertRaises(expected_exception) as ctx:
            await func(*args, **kwargs)
        return ctx

    async def assertRaisesRegexAsync(self, expected_exception, expected_regex,  # noqa: N802
                                     func, *args, **kwargs):
        """Async counterpart of ``assertRaisesRegex(exc, regex, callable, ...)``."""
        with self.assertRaisesRegex(expected_exception, expected_regex) as ctx:
            await func(*args, **kwargs)
        return ctx


def _async_method_names(cls):
    return [name for name in dir(cls)
            if not name.startswith('__')
            and inspect.iscoroutinefunction(getattr(cls, name, None))]


class _ValidatorMock(mock.MagicMock):
    """Spec'd MagicMock whose un-configured async methods resolve to a
    MagicMock (what a sync MagicMock method returns) instead of to another
    AsyncMock. Children are created lazily, on first access."""

    def _get_child_mock(self, **kw):
        child = super()._get_child_mock(**kw)
        if isinstance(child, mock.AsyncMock):
            child.return_value = mock.MagicMock()
        return child


def _validator_mock(spec, wraps=None):
    if wraps is None:
        return _ValidatorMock(spec=spec)
    # Mirror ``MagicMock(wraps=validator)``: un-configured calls fall through
    # to the real validator, with async methods wrapped by AsyncMock.
    m = mock.MagicMock(wraps=wraps)
    for name in _async_method_names(spec):
        setattr(m, name, mock.AsyncMock(wraps=getattr(wraps, name)))
    return m


def validator_mock(spec=None, wraps=None):
    """A mock OAuth2/OIDC ``RequestValidator``.

    Every ``async def`` validator method is an ``AsyncMock`` so the library
    can await it, while ``return_value``/``side_effect`` configuration keeps
    working as with a plain ``MagicMock``. Pass ``wraps=<validator>`` to get
    ``MagicMock(wraps=...)`` semantics.
    """
    if spec is None and wraps is not None:
        spec = type(wraps)
    if spec is None:
        spec = OIDCRequestValidator
    return _validator_mock(spec, wraps)


def oauth1_validator_mock(wraps=None):
    """A mock OAuth1 ``RequestValidator`` (see :func:`validator_mock`)."""
    return _validator_mock(OAuth1RequestValidator, wraps)


# URL comparison where query param order is insignificant
def url_equals(self, a, b, parse_fragment=False):
    parsed_a = urlparse.urlparse(a, allow_fragments=parse_fragment)
    parsed_b = urlparse.urlparse(b, allow_fragments=parse_fragment)
    query_a = urlparse.parse_qsl(parsed_a.query)
    query_b = urlparse.parse_qsl(parsed_b.query)
    if parse_fragment:
        fragment_a = urlparse.parse_qsl(parsed_a.fragment)
        fragment_b = urlparse.parse_qsl(parsed_b.fragment)
        self.assertCountEqual(fragment_a, fragment_b)
    else:
        self.assertEqual(parsed_a.fragment, parsed_b.fragment)
    self.assertEqual(parsed_a.scheme, parsed_b.scheme)
    self.assertEqual(parsed_a.netloc, parsed_b.netloc)
    self.assertEqual(parsed_a.path, parsed_b.path)
    self.assertEqual(parsed_a.params, parsed_b.params)
    self.assertEqual(parsed_a.username, parsed_b.username)
    self.assertEqual(parsed_a.password, parsed_b.password)
    self.assertEqual(parsed_a.hostname, parsed_b.hostname)
    self.assertEqual(parsed_a.port, parsed_b.port)
    self.assertCountEqual(query_a, query_b)


TestCase.assertURLEqual = url_equals
unittest.TestCase.assertURLEqual = url_equals

# Form body comparison where order is insignificant
unittest.TestCase.assertFormBodyEqual = TestCase.assertFormBodyEqual = lambda self, a, b: self.assertCountEqual(
        urlparse.parse_qsl(a), urlparse.parse_qsl(b))
