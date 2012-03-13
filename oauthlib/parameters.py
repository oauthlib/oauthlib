# -*- coding: utf-8 -*-

"""
oauthlib.parameters
~~~~~~~~~~~~~~~~~~~

This module contains methods related to `section 3.5`_ of the OAuth 1.0a spec.

.. _`section 3.5`: http://tools.ietf.org/html/rfc5849#section-3.5
"""

from urlparse import urlparse, urlunparse, parse_qsl
from utils import filter_params, urlencode


def order_params(target):
    """Decorator which reorders params contents to start with oauth_* params

    Assumes the decorated method takes a params dict or list of tuples as its
    first argument.
    """
    def wrapper(params, *args, **kwargs):
        params = order_oauth_parameters(params)
        return target(params, *args, **kwargs)

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


@filter_params
def prepare_authorization_header(params, realm=None):
    """Prepare the Authorization header.

    Per `section 3.5.1`_ of the spec.

    .. _`section 3.5.1`: http://tools.ietf.org/html/rfc5849#section-3.5.1

    """
    # TODO: Realm should always be the first parameter, right?
    # Doesn't seem to be specified.
    if realm:
        params.insert(0, ("realm", realm))

    # Only oauth_ and realm parameters should remain by this point.
    return 'OAuth ' + ','.join(['='.join([k, v]) for k, v in params])


@order_params
def prepare_form_encoded_body(params):
    """Prepare the Form-Encoded Body.

    Per `section 3.5.2`_ of the spec.

    params: OAuth parameters and data (i.e. POST data).

    .. _`section 3.5.2`: http://tools.ietf.org/html/rfc5849#section-3.5.2

    """
    return urlencode(params)


@order_params
def prepare_request_uri_query(params, url):
    """Prepare the Request URI Query.

    Per `section 3.5.3`_ of the spec.

    params: OAuth parameters and data (i.e. POST data).
    url: The request url. Query components will be removed.

    .. _`section 3.5.3`: http://tools.ietf.org/html/rfc5849#section-3.5.3

    """
    # convert dict to list of tuples
    if isinstance(params, dict):
        params = params.items()

    # append OAuth params to the existing set of query components
    sch, net, path, par, query, fra = urlparse(url)
    queryparams = parse_qsl(query, True)
    queryparams.extend(params)
    queryparams.sort(key=lambda i: i[0].startswith('oauth_'))
    query = urlencode(queryparams)
    return urlunparse((sch, net, path, par, query, fra))
