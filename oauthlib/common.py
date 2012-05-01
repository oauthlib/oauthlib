# -*- coding: utf-8 -*-
from __future__ import absolute_import

"""
oauthlib.common
~~~~~~~~~~~~~~

This module provides data structures and utilities common
to all implementations of OAuth.
"""

import re
import urlparse


always_safe = (u'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
               u'abcdefghijklmnopqrstuvwxyz'
               u'0123456789' u'_.-')
_safe_map = {}
for i, c in zip(xrange(256), str(bytearray(xrange(256)))):
    _safe_map[c] = (c if (i < 128 and c in always_safe) else \
        '%{0:02X}'.format(i)).decode('utf-8')
_safe_quoters = {}


def quote(s, safe=u'/'):
    """A unicode-safe version of urllib.quote"""
    # fastpath
    if not s:
        if s is None:
            raise TypeError('None object cannot be quoted')
        return s
    cachekey = (safe, always_safe)
    try:
        (quoter, safe) = _safe_quoters[cachekey]
    except KeyError:
        safe_map = _safe_map.copy()
        safe_map.update([(c, c) for c in safe])
        quoter = safe_map.__getitem__
        safe = always_safe + safe
        _safe_quoters[cachekey] = (quoter, safe)
    if not s.rstrip(safe):
        return s
    return u''.join(map(quoter, s))

_hexdig = u'0123456789ABCDEFabcdef'
_hextochr = dict((a + b, unichr(int(a + b, 16)))
                 for a in _hexdig for b in _hexdig)


def unquote(s):
    """A unicode-safe version of urllib.unquote"""
    res = s.split('%')
    # fastpath
    if len(res) == 1:
        return s
    s = res[0]
    for item in res[1:]:
        try:
            s += _hextochr[item[:2]] + item[2:]
        except KeyError:
            s += u'%' + item
        except UnicodeDecodeError:
            s += unichr(int(item[:2], 16)) + item[2:]
    return s


def unicode_params(params):
    """Ensures that all parameters in a list of 2-element tuples are unicode"""
    clean = []
    for k, v in params:
        clean.append((
            unicode(k, 'utf-8') if isinstance(k, str) else k,
            unicode(v, 'utf-8') if isinstance(v, str) else v))
    return clean


urlencoded = set(always_safe) | set(u'=&;%+~')


def urldecode(query):
    """Decode a query string in x-www-form-urlencoded format into a sequence
    of two-element tuples.

    Unlike urlparse.parse_qsl(..., strict_parsing=True) urldecode will enforce
    correct formatting of the query string by validation. If validation fails
    a ValueError will be raised. urllib.parse_qsl will only raise errors if
    any of name-value pairs omits the equals sign.
    """
    # Check if query contains invalid characters
    if query and not set(query) <= urlencoded:
        raise ValueError('Invalid characters in query string.')

    # Check for correctly hex encoded values using a regular expression
    # All encoded values begin with % followed by two hex characters
    # correct = %00, %A0, %0A, %FF
    # invalid = %G0, %5H, %PO
    invalid_hex = u'%[^0-9A-Fa-f]|%[0-9A-Fa-f][^0-9A-Fa-f]'
    if len(re.findall(invalid_hex, query)):
        raise ValueError('Invalid hex encoding in query string.')

    # We want to allow queries such as "c2" whereas urlparse.parse_qsl
    # with the strict_parsing flag will not.
    params = urlparse.parse_qsl(query, keep_blank_values=True)

    # unicode all the things
    return unicode_params(params)


def extract_params(raw):
    """Extract parameters and return them as a list of 2-tuples.

    Will successfully extract parameters from urlencoded query strings,
    dicts, or lists of 2-tuples. Empty strings/dicts/lists will return an
    empty list of parameters. Any other input will result in a return
    value of None.
    """
    if isinstance(raw, basestring):
        try:
            params = urldecode(raw)
        except ValueError:
            params = None
    elif hasattr(raw, '__iter__'):
        try:
            dict(raw)
        except ValueError:
            params = None
        except TypeError:
            params = None
        else:
            params = list(raw.items() if isinstance(raw, dict) else raw)
            params = unicode_params(params)
    else:
        params = None

    return params


class Request(object):
    """A malleable representation of a signable HTTP request.

    Body argument may contain any data, but parameters will only be decoded if
    they are one of:

    * urlencoded query string
    * dict
    * list of 2-tuples

    Anything else will be treated as raw body data to be passed through
    unmolested.
    """

    def __init__(self, uri, http_method=u'GET', body=None, headers=None):
        self.uri = uri
        self.http_method = http_method
        self.headers = headers or {}
        self.body = body
        self.decoded_body = extract_params(body)
        self.oauth_params = []

    @property
    def uri_query(self):
        return urlparse.urlparse(self.uri).query

    @property
    def uri_query_params(self):
        return urlparse.parse_qsl(self.uri_query, keep_blank_values=True,
                                  strict_parsing=True)
