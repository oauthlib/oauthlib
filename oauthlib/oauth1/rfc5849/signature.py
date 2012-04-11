from __future__ import absolute_import
"""
3.4.  Signature

This module represents a direct implementation of section 3.4 of the spec.

http://tools.ietf.org/html/rfc5849#section-3.4

Terminology:
 * Client: software interfacing with an OAuth API
 * Server: the API provider
 * Resource Owner: the user who is granting authorization to the client

Steps for signing a request:

1. Collect parameters from the uri query, auth header, & body
2. Normalize those parameters
3. Normalize the uri
4. Pass the normalized uri, normalized parameters, and http method to
   construct the base string
5. Pass the base string and any keys needed to a signing function
"""

import binascii
import hashlib
import hmac
import urlparse
from . import utils


def construct_base_string(http_method, base_string_uri,
        normalized_encoded_request_parameters):
    """Construct the final base string to use for signing.
    Per `section 3.4.1.1`_ of the spec.

    .. _`section 3.4.1.1`: http://tools.ietf.org/html/rfc5849#section-3.4.1.1
    """

    return '&'.join((
        utils.escape(http_method.upper()),
        utils.escape(base_string_uri),
        utils.escape(normalized_encoded_request_parameters),
    ))


def normalize_base_string_uri(uri):
    """Normalize a uri for use in constructing a base string.
    Per `section 3.4.1.2`_ of the spec.

    .. _`section 3.4.1.2`: http://tools.ietf.org/html/rfc5849#section-3.4.1.2
    """
    if not isinstance(uri, unicode):
        raise ValueError('uri must be a unicode object.')

    scheme, netloc, path, params, query, fragment = urlparse.urlparse(uri)

    # scheme and netloc must be lowercase (3.4.1.2 #1)
    scheme = scheme.lower()
    netloc = netloc.lower()

    # strip port 80 from host if expliticly present (3.4.1.2 #3)
    default_ports = (
        (u'http', u'80'),
        (u'https', u'443'),
    )
    if u':' in netloc:
        host, port = netloc.split(u':', 1)
        if (scheme, port) in default_ports:
            netloc = host

    return urlparse.urlunparse((scheme, netloc, path, '', '', ''))


def collect_parameters(uri_query='', body='', headers=None,
        exclude_oauth_signature=True):
    """Collect parameters from the uri query, authorization header, and request
    body.

    String paramters will be decoded into unicode using utf-8.
    Parameters starting with `oauth_` will be unescaped.
    Per `section 3.4.1.3.1`_ of the spec.

    .. _`section 3.4.1.3.1`: http://tools.ietf.org/html/rfc5849#section-3.4.1.3.1
    """
    headers = headers or {}
    params = []

    if uri_query:
        params.extend(urlparse.parse_qsl(uri_query, keep_blank_values=True))

    if headers:
        # look for an authorization header (case-insensitive)
        headers_lower = dict((k.lower(), v) for k, v in headers.items())
        authorization_header = headers_lower.get('authorization')
        if authorization_header is not None:
            params.extend(utils.parse_authorization_header(
                authorization_header))

    if isinstance(body, (str, unicode)):
        params.extend(urlparse.parse_qsl(body, keep_blank_values=True))
    elif isinstance(body, dict):
        params.extend(body.items())
    else:
        try:
            params.extend(body)
        except TypeError:
            raise ValueError("Body must be a string, dict, or iterable")

    # ensure all paramters are unicode and not escaped
    unicode_params = []
    for k, v in params:
        if isinstance(k, str):
            k = k.decode('utf-8')
        if isinstance(v, str):
            if v.startswith('oauth_'):
                v = utils.unescape(v)
            else:
                v = v.decode('utf-8')
        unicode_params.append((k, v))

    # exclude particular parameters according to the spec
    exclude_params = [
        u'realm',
    ]
    if exclude_oauth_signature:
        exclude_params.append(u'oauth_signature')

    return filter(lambda i: i[0] not in exclude_params, unicode_params)


def normalize_parameters(params):
    """Normalize querystring parameters for use in constructing a base string.
    Per `section 3.4.1.3.2`_ of the spec.

    .. _`section 3.4.1.3.2`: http://tools.ietf.org/html/rfc5849#section-3.4.1.3.2
    """

    # Escape key values before sorting
    key_values = [(utils.escape(k), utils.escape(v)) for k, v in params]

    # Sort lexicographically, first after key, then after value.
    key_values.sort()

    # Combine key value pairs into a string and return.
    return u'&'.join([u'{0}={1}'.format(k, v) for k, v in key_values])


def sign_hmac_sha1(base_string, client_secret, resource_owner_secret):
    """Sign a request using HMAC-SHA1.

    Per `section 3.4.2`_ of the spec.

    .. _`section 3.4.2`: http://tools.ietf.org/html/rfc5849#section-3.4.2
    """

    key = '&'.join((utils.escape(client_secret),
        utils.escape(resource_owner_secret)))
    signature = hmac.new(key, base_string, hashlib.sha1)
    return binascii.b2a_base64(signature.digest())[:-1].decode('utf-8')


def sign_rsa_sha1(base_string, rsa_private_key):
    """Sign a request using RSASSA-PKCS #1 v1.5.

    Per `section 3.4.3`_ of the spec.

    Note this method requires the PyCrypto library.

    .. _`section 3.4.3`: http://tools.ietf.org/html/rfc5849#section-3.4.3

    """
    from Crypto.PublicKey import RSA
    from Crypto.Signature import PKCS1_v1_5
    from Crypto.Hash import SHA

    key = RSA.importKey(rsa_private_key)
    h = SHA.new(base_string)
    p = PKCS1_v1_5.new(key)
    return binascii.b2a_base64(p.sign(h))[:-1].decode('utf-8')


def sign_plaintext(client_secret, resource_owner_secret):
    """Sign a request using plaintext.

    Per `section 3.4.4`_ of the spec.

    .. _`section 3.4.4`: http://tools.ietf.org/html/rfc5849#section-3.4.4

    """
    return u'&'.join((utils.escape(client_secret),
        utils.escape(resource_owner_secret)))
