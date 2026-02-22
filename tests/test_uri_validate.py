from datetime import datetime

import pytest

from oauthlib.uri_validate import is_absolute_uri


def test_is_absolute_uri():
    assert is_absolute_uri("schema://example.com/path") is not None
    assert is_absolute_uri("https://example.com/path") is not None
    assert is_absolute_uri("https://example.com") is not None
    assert is_absolute_uri("https://example.com:443/path") is not None
    assert is_absolute_uri("https://example.com:443/") is not None
    assert is_absolute_uri("https://example.com:443") is not None
    assert is_absolute_uri("http://example.com") is not None
    assert is_absolute_uri("http://example.com/path") is not None
    assert is_absolute_uri("http://example.com:80/path") is not None


def test_query():
    assert is_absolute_uri("http://example.com:80/path?foo") is not None
    assert is_absolute_uri("http://example.com:80/path?foo=bar") is not None
    assert is_absolute_uri("http://example.com:80/path?foo=bar&fruit=banana") is not None


def test_fragment_forbidden():
    assert is_absolute_uri("http://example.com:80/path#foo") is None
    assert is_absolute_uri("http://example.com:80/path#foo=bar") is None
    assert is_absolute_uri("http://example.com:80/path#foo=bar&fruit=banana") is None


def test_combined_forbidden():
    assert is_absolute_uri("http://example.com:80/path?foo#bar") is None
    assert is_absolute_uri("http://example.com:80/path?foo&bar#fruit") is None
    assert is_absolute_uri("http://example.com:80/path?foo=1&bar#fruit=banana") is None
    assert is_absolute_uri("http://example.com:80/path?foo=1&bar=2#fruit=banana&bar=foo") is None


def test_custom_scheme():
    assert is_absolute_uri("com.example.bundle.id://") is not None


def test_ipv6_bracket():
    assert is_absolute_uri("http://[::1]:38432/path") is not None
    assert is_absolute_uri("http://[::1]/path") is not None
    assert is_absolute_uri("http://[fd01:0001::1]/path") is not None
    assert is_absolute_uri("http://[fd01:1::1]/path") is not None
    assert is_absolute_uri("http://[0123:4567:89ab:cdef:0123:4567:89ab:cdef]/path") is not None
    assert is_absolute_uri("http://[0123:4567:89ab:cdef:0123:4567:89ab:cdef]:8080/path") is not None


@pytest.mark.skip(reason="ipv6 edge-cases not supported")
def test_ipv6_edge_cases():
    assert is_absolute_uri("http://2001:db8::") is not None
    assert is_absolute_uri("http://::1234:5678") is not None
    assert is_absolute_uri("http://2001:db8::1234:5678") is not None
    assert is_absolute_uri("http://2001:db8:3333:4444:5555:6666:7777:8888") is not None
    assert is_absolute_uri("http://2001:db8:3333:4444:CCCC:DDDD:EEEE:FFFF") is not None
    assert is_absolute_uri("http://0123:4567:89ab:cdef:0123:4567:89ab:cdef/path") is not None
    assert is_absolute_uri("http://::") is not None
    assert is_absolute_uri("http://2001:0db8:0001:0000:0000:0ab9:C0A8:0102") is not None


@pytest.mark.skip(reason="ipv6 dual ipv4 not supported")
def test_ipv6_dual():
    assert is_absolute_uri("http://2001:db8:3333:4444:5555:6666:1.2.3.4") is not None
    assert is_absolute_uri("http://::11.22.33.44") is not None
    assert is_absolute_uri("http://2001:db8::123.123.123.123") is not None
    assert is_absolute_uri("http://::1234:5678:91.123.4.56") is not None
    assert is_absolute_uri("http://::1234:5678:1.2.3.4") is not None
    assert is_absolute_uri("http://2001:db8::1234:5678:5.6.7.8") is not None


def test_ipv4():
    assert is_absolute_uri("http://127.0.0.1:38432/") is not None
    assert is_absolute_uri("http://127.0.0.1:38432/") is not None
    assert is_absolute_uri("http://127.1:38432/") is not None


def test_failures():
    assert is_absolute_uri("http://example.com:notaport/path") is None
    assert is_absolute_uri("wrong") is None
    assert is_absolute_uri("http://[:1]:38432/path") is None
    assert is_absolute_uri("http://[abcd:efgh::1]/") is None


def test_recursive_regex():
    t0 = datetime.now()
    is_absolute_uri("http://[::::::::::::::::::::::::::]/path")
    t1 = datetime.now()
    spent = t1 - t0
    assert spent.total_seconds() < 0.1, "possible recursive loop detected"
