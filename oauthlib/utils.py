# -*- coding: utf-8 -*-

"""
oauthlib.utils
~~~~~~~~~~~~~~

This module contains utility methods used by various parts of the OAuth
spec.
"""

import time
import urllib
import urllib2
from random import getrandbits


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
    is_oauth = lambda kv: kv[0].startswith("oauth_")
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
    return str(int(time.time()))


def generate_nonce():
    """Generate pseudorandom nonce that is unlikely to repeat.

    Per `section 3.3`_ of the spec.

    A random 64-bit number is appended to the epoch timestamp for both
    randomness and to decrease the likelihood of collisions.

    .. _`section 3.3`: http://tools.ietf.org/html/rfc5849#section-3.3
    """
    return str(getrandbits(64)) + generate_timestamp()


def escape(s):
    """Escape a string in an OAuth-compatible fashion.

    Per `section 3.6`_ of the spec.

    .. _`section 3.6`: http://tools.ietf.org/html/rfc5849#section-3.6

    """
    if not isinstance(s, unicode):
        raise ValueError('Only unicode objects are escapable.')
    return urllib.quote(s.encode('utf-8'), safe='~')


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

