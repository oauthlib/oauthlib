# -*- coding: utf-8 -*-

"""
oauthlib.utils
~~~~~~~~~~~~~~

This module contains utility methods used by various parts of the OAuth
spec.
"""

import time
import urllib
from random import getrandbits


def filter_oauth_params(params):
    """Removes all non oauth parameters from a dict or a list of params.
    """
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

    :param s: The string to be escaped.
    :return: An url encoded string.

    .. _`section 3.6`: http://tools.ietf.org/html/rfc5849#section-3.6

    """
    if not isinstance(s, unicode):
        raise ValueError('Only unicode objects are escapable.')
    return urllib.quote(s.encode('utf-8'), safe='~')
