# -*- coding: utf-8 -*-
from __future__ import absolute_import

"""
oauthlib.parameters
~~~~~~~~~~~~~~~~~~~

This module contains methods related to `section 3.5`_ of the OAuth 1.0a spec.

.. _`section 3.5`: http://tools.ietf.org/html/rfc5849#section-3.5
"""

from urlparse import urlparse, urlunparse, parse_qsl
from . import utils


def order_params(target):
    """Decorator which reorders params contents to start with oauth_* params

    Assumes the decorated method takes a params dict or list of tuples as its
    first argument.
    """
    def wrapper(params, *args, **kwargs):
        ordered_params = order_oauth_parameters(params)
        return target(ordered_params, *args, **kwargs)

    wrapper.__doc__ = target.__doc__
    return wrapper


def order_oauth_parameters(params):
    """Order a parameters dict or list of tuples with OAuth ones first

    Per `section 3.5`_ of the spec.

    .. _`section 3.5`: http://tools.ietf.org/html/rfc5849#section-3.5
    """
    # Convert dictionaries to list of tuples
    if isinstance(params, dict):
        params = params.items()

    ordered = []
    for k, v in params:
        if k.startswith("oauth_"):
            ordered.insert(0, (k, v))
        else:
            ordered.append((k, v))

    return ordered


@utils.filter_params
def prepare_headers(params, headers=None, realm=None):
    """**Prepare the Authorization header.**
    Per `section 3.5.1`_ of the spec.

    Protocol parameters can be transmitted using the HTTP "Authorization"
    header field as defined by `RFC2617`_ with the auth-scheme name set to
    "OAuth" (case insensitive).

    For example::

        Authorization: OAuth realm="Example",
            oauth_consumer_key="0685bd9184jfhq22",
            oauth_token="ad180jjd733klru7",
            oauth_signature_method="HMAC-SHA1",
            oauth_signature="wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D",
            oauth_timestamp="137131200",
            oauth_nonce="4572616e48616d6d65724c61686176",
            oauth_version="1.0"


    .. _`section 3.5.1`: http://tools.ietf.org/html/rfc5849#section-3.5.1
    .. _`RFC2617`: http://tools.ietf.org/html/rfc2617
    """

    headers = headers or {}

    # Protocol parameters SHALL be included in the "Authorization" header
    # field as follows:
    authorization_header_parameters_parts = []
    for oauth_parameter_name, value in params:
        # 1.  Parameter names and values are encoded per Parameter Encoding
        #     (`Section 3.6`_)
        #
        # .. _`Section 3.6`: http://tools.ietf.org/html/rfc5849#section-3.6
        escaped_name = utils.escape(oauth_parameter_name)
        escaped_value = utils.escape(value)

        # 2.  Each parameter's name is immediately followed by an "=" character
        #     (ASCII code 61), a """ character (ASCII code 34), the parameter
        #     value (MAY be empty), and another """ character (ASCII code 34).
        part = u'{0}="{1}"'.format(escaped_name, escaped_value)

        authorization_header_parameters_parts.append(part)

    # 3.  Parameters are separated by a "," character (ASCII code 44) and
    #     OPTIONAL linear whitespace per `RFC2617`_.
    #
    # .. _`RFC2617`: http://tools.ietf.org/html/rfc2617
    authorization_header_parameters = ', '.join(
        authorization_header_parameters_parts)

    # 4.  The OPTIONAL "realm" parameter MAY be added and interpreted per
    #     `RFC2617 section 1.2`_.
    #
    # .. _`RFC2617 section 1.2`: http://tools.ietf.org/html/rfc2617#section-1.2
    if realm:
        # NOTE: realm should *not* be escaped
        authorization_header_parameters = (u'realm="%s", ' % realm +
            authorization_header_parameters)

    # the auth-scheme name set to "OAuth" (case insensitive).
    authorization_header = u'OAuth %s' % authorization_header_parameters

    # contribute the Authorization header to the given headers
    full_headers = {}
    full_headers.update(headers)
    full_headers[u'Authorization'] = authorization_header
    return full_headers


def _add_params_to_qs(query, params):
    queryparams = parse_qsl(query, True)
    queryparams.extend(params)
    queryparams.sort(key=lambda i: i[0].startswith('oauth_'))
    return utils.urlencode(queryparams)


@order_params
def prepare_form_encoded_body(params, body):
    """Prepare the Form-Encoded Body.

    Per `section 3.5.2`_ of the spec.

    params: OAuth parameters and data (i.e. POST data).

    .. _`section 3.5.2`: http://tools.ietf.org/html/rfc5849#section-3.5.2

    """
    # append OAuth params to the existing body
    return _add_params_to_qs(body, params)


@order_params
def prepare_request_uri_query(params, uri):
    """Prepare the Request URI Query.

    Per `section 3.5.3`_ of the spec.

    params: OAuth parameters and data (i.e. POST data).
    url: The request url. Query components will be removed.

    .. _`section 3.5.3`: http://tools.ietf.org/html/rfc5849#section-3.5.3

    """
    # append OAuth params to the existing set of query components
    sch, net, path, par, query, fra = urlparse(uri)
    query = _add_params_to_qs(query, params)
    return urlunparse((sch, net, path, par, query, fra))
