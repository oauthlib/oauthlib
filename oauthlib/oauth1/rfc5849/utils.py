# -*- coding: utf-8 -*-

"""
oauthlib.utils
~~~~~~~~~~~~~~

This module contains utility methods used by various parts of the OAuth
spec.
"""

import string
import time
from random import getrandbits, choice

UNICODE_ASCII_CHARACTER_SET = (string.ascii_letters.decode('ascii') +
    string.digits.decode('ascii'))


def filter_params(target):
    """Decorator which filters params to remove non-oauth_* parameters

    Assumes the decorated method takes a params dict or list of tuples as its
    first argument.
    """
    def wrapper(params, *args, **kwargs):
        params = filter_oauth_params(params)
        return target(params, *args, **kwargs)

    wrapper.__doc__ = target.__doc__
    return wrapper


def filter_oauth_params(params):
    """Removes all non oauth parameters from a dict or a list of params."""
    is_oauth = lambda kv: kv[0].startswith(u"oauth_")
    if isinstance(params, dict):
        return filter(is_oauth, params.items())
    else:
        return filter(is_oauth, params)


def generate_timestamp():
    """Get seconds since epoch (UTC).

    Per `section 3.3`_ of the spec.

    .. _`section 3.3`: http://tools.ietf.org/html/rfc5849#section-3.3
    """
    return unicode(int(time.time()))


def generate_nonce():
    """Generate pseudorandom nonce that is unlikely to repeat.

    Per `section 3.3`_ of the spec.

    A random 64-bit number is appended to the epoch timestamp for both
    randomness and to decrease the likelihood of collisions.

    .. _`section 3.3`: http://tools.ietf.org/html/rfc5849#section-3.3
    """
    return unicode(getrandbits(64)) + generate_timestamp()


def generate_token(length=20, chars=UNICODE_ASCII_CHARACTER_SET):
    """Generates a generic OAuth token

    According to `section 2`_ of the spec, the method of token
    construction is undefined. This implementation is simply a random selection
    of `length` choices from `chars`.

    Credit to Ignacio Vazquez-Abrams for his excellent `Stackoverflow answer`_

    .. _`Stackoverflow answer` : http://stackoverflow.com/questions/2257441/
        python-random-string-generation-with-upper-case-letters-and-digits

    """
    return u''.join(choice(chars) for x in range(length))


always_safe = (u'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
               u'abcdefghijklmnopqrstuvwxyz'
               u'0123456789' u'_.-')
_safe_map = {}
for i, c in zip(xrange(256), str(bytearray(xrange(256)))):
    _safe_map[c] = (c if (i < 128 and c in always_safe) else \
        '%{:02X}'.format(i)).decode('utf-8')
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


def escape(u):
    """Escape a unicode string in an OAuth-compatible fashion.

    Per `section 3.6`_ of the spec.

    .. _`section 3.6`: http://tools.ietf.org/html/rfc5849#section-3.6

    """
    if not isinstance(u, unicode):
        raise ValueError('Only unicode objects are escapable.')
    # Letters, digits, and the characters '_.-' are already treated as safe
    # by urllib.quote(). We need to add '~' to fully support rfc5849.
    return quote(u, safe='~')


def unescape(u):
    if not isinstance(u, unicode):
        raise ValueError('Only unicode objects are unescapable.')
    return unquote(u)


def urlencode(query):
    """Encode a sequence of two-element tuples or dictionary into a URL query string.

    Operates using an OAuth-safe escape() method, in contrast to urllib.urlencode.
    """
    # Convert dictionaries to list of tuples
    if isinstance(query, dict):
        query = query.items()
    return u"&".join([u'='.join([escape(k), escape(v)]) for k, v in query])


def parse_keqv_list(l):
    """A unicode-safe version of urllib2.parse_keqv_list"""
    parsed = {}
    for elt in l:
        k, v = elt.split(u'=', 1)
        if v[0] == u'"' and v[-1] == u'"':
            v = v[1:-1]
        parsed[k] = v
    return parsed


def parse_http_list(s):
    """A unicode-safe version of urllib2.parse_http_list"""
    res = []
    part = u''

    escape = quote = False
    for cur in s:
        if escape:
            part += cur
            escape = False
            continue
        if quote:
            if cur == u'\\':
                escape = True
                continue
            elif cur == u'"':
                quote = False
            part += cur
            continue

        if cur == u',':
            res.append(part)
            part = u''
            continue

        if cur == u'"':
            quote = True

        part += cur

    # append last part
    if part:
        res.append(part)

    return [part.strip() for part in res]


def parse_authorization_header(authorization_header):
    """Parse an OAuth authorization header into a list of 2-tuples"""
    auth_scheme = u'OAuth '
    if authorization_header.startswith(auth_scheme):
        authorization_header = authorization_header.replace(auth_scheme, u'', 1)
    items = parse_http_list(authorization_header)
    try:
        return parse_keqv_list(items).items()
    except ValueError:
        raise ValueError('Malformed authorization header')
