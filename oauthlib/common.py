# -*- coding: utf-8 -*-
from __future__ import absolute_import

"""
oauthlib.common
~~~~~~~~~~~~~~

This module provides data structures and utilities common
to all implementations of OAuth.
"""

from urlparse import parse_qsl, urlparse


def extract_params(raw):
    """Extract parameters and return them as a list of 2-tuples.

    Will successfully extract parameters from urlencoded query strings,
    dicts, or lists of 2-tuples. Empty strings/dicts/lists will return an
    empty list of parameters. Any other input will result in a return
    value of None.
    """
    if isinstance(raw, basestring):
        if len(raw) == 0:
            params = []  # short-circuit, strict parsing chokes on blank
        else:
            # FIXME how do we handle partly invalid param strings like "c2&a3=2+q"?
            # With strict_parsing it's all or nothing. :(
            try:
                # params = parse_qsl(raw, keep_blank_values=True, strict_parsing=True)
                params = parse_qsl(raw, keep_blank_values=True)

                # Prevent the degenerate case where strict_parsing=False allows
                # any string as a valid, valueless parameter. This means that an
                # input like u'foo bar' will not result in [(u'foo bar', u'')].
                if len(params) == 1 and params[0][1] == '':
                    raise ValueError
            except ValueError:
                params = None  # No parameters to see here, move along.
    elif hasattr(raw, '__iter__'):
        try:
            dict(raw)
        except ValueError:
            params = None
        except TypeError:
            params = None
        else:
            params = list(raw.items() if isinstance(raw, dict) else raw)
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
        self.body = extract_params(body or [])
        if self.body == None:
            self.body = body
            self.body_has_params = False
        elif self.body == []:
            self.body_has_params = False
        else:
            self.body_has_params = True
        self.oauth_params = []

    @property
    def uri_query(self):
        return urlparse(self.uri).query

    @property
    def uri_query_params(self):
        return parse_qsl(self.uri_query, keep_blank_values=True,
                                  strict_parsing=True)
