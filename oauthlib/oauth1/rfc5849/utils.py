# -*- coding: utf-8 -*-

"""
oauthlib.utils
~~~~~~~~~~~~~~

This module contains utility methods used by various parts of the OAuth
spec.
"""

import string
import time
import urllib
import urllib2
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


def utf8_str(s):
    """Convert unicode to utf-8."""
    if isinstance(s, unicode):
        return s.encode("utf-8")
    else:
        return str(s)


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


def escape(u):
    """Escape a string in an OAuth-compatible fashion.

    Per `section 3.6`_ of the spec.

    .. _`section 3.6`: http://tools.ietf.org/html/rfc5849#section-3.6

    """
    if not isinstance(u, unicode):
        raise ValueError('Only unicode objects are escapable.')
    return urllib.quote(u.encode('utf-8'), safe='~')


def unescape(s):
    if not isinstance(s, str):
        raise ValueError('Only string objects are unescapable.')
    return urllib.unquote(s, safe='~').decode('utf-8')


def urlencode(query):
    """Encode a sequence of two-element tuples or dictionary into a URL query string.

    Operates using an OAuth-safe escape() method, in contrast to urllib.urlenocde.
    """
    # Convert dictionaries to list of tuples
    if isinstance(query, dict):
        query = query.items()
    return "&".join(['='.join([escape(k), escape(v)]) for k, v in query])


def parse_authorization_header(authorization_header):
    """Parse an OAuth authorization header into a list of 2-tuples"""
    auth_scheme = 'OAuth '
    if authorization_header.startswith(auth_scheme):
        authorization_header = authorization_header.replace(auth_scheme, '', 1)
    items = urllib2.parse_http_list(authorization_header)
    try:
        return urllib2.parse_keqv_list(items).items()
    except ValueError:
        raise ValueError('Malformed authorization header')
