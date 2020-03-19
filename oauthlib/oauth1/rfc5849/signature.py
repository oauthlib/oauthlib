# -*- coding: utf-8 -*-
"""
oauthlib.oauth1.rfc5849.signature
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This module represents a direct implementation of `section 3.4`_ of the spec.

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

.. _`section 3.4`: https://tools.ietf.org/html/rfc5849#section-3.4
"""
import binascii
import hashlib
import hmac
import logging

from oauthlib.common import extract_params, safe_string_equals, urldecode
import urllib.parse as urlparse

from . import utils


log = logging.getLogger(__name__)


# ================================================================
# Common functions

def signature_base_string(http_method, base_str_uri,
                          normalized_encoded_request_parameters):
    """**Construct the signature base string.**
    Per `section 3.4.1.1`_ of the spec.

    For example, the HTTP request::

        POST /request?b5=%3D%253D&a3=a&c%40=&a2=r%20b HTTP/1.1
        Host: example.com
        Content-Type: application/x-www-form-urlencoded
        Authorization: OAuth realm="Example",
            oauth_consumer_key="9djdj82h48djs9d2",
            oauth_token="kkk9d7dh3k39sjv7",
            oauth_signature_method="HMAC-SHA1",
            oauth_timestamp="137131201",
            oauth_nonce="7d8f3e4a",
            oauth_signature="bYT5CMsGcbgUdFHObYMEfcx6bsw%3D"

        c2&a3=2+q

    is represented by the following signature base string (line breaks
    are for display purposes only)::

        POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q
        %26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_
        key%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a%26oauth_signature_m
        ethod%3DHMAC-SHA1%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk
        9d7dh3k39sjv7

    .. _`section 3.4.1.1`: https://tools.ietf.org/html/rfc5849#section-3.4.1.1
    """

    # The signature base string is constructed by concatenating together,
    # in order, the following HTTP request elements:

    # 1.  The HTTP request method in uppercase.  For example: "HEAD",
    #     "GET", "POST", etc.  If the request uses a custom HTTP method, it
    #     MUST be encoded (`Section 3.6`_).
    #
    # .. _`Section 3.6`: https://tools.ietf.org/html/rfc5849#section-3.6
    base_string = utils.escape(http_method.upper())

    # 2.  An "&" character (ASCII code 38).
    base_string += '&'

    # 3.  The base string URI from `Section 3.4.1.2`_, after being encoded
    #     (`Section 3.6`_).
    #
    # .. _`Section 3.4.1.2`: https://tools.ietf.org/html/rfc5849#section-3.4.1.2
    # .. _`Section 3.6`: https://tools.ietf.org/html/rfc5849#section-3.6
    base_string += utils.escape(base_str_uri)

    # 4.  An "&" character (ASCII code 38).
    base_string += '&'

    # 5.  The request parameters as normalized in `Section 3.4.1.3.2`_, after
    #     being encoded (`Section 3.6`).
    #
    # .. _`Section 3.4.1.3.2`: https://tools.ietf.org/html/rfc5849#section-3.4.1.3.2
    # .. _`Section 3.6`: https://tools.ietf.org/html/rfc5849#section-3.6
    base_string += utils.escape(normalized_encoded_request_parameters)

    return base_string


def base_string_uri(uri, host=None):
    """**Base String URI**
    Per `section 3.4.1.2`_ of RFC 5849.

    For example, the HTTP request::

        GET /r%20v/X?id=123 HTTP/1.1
        Host: EXAMPLE.COM:80

    is represented by the base string URI: "http://example.com/r%20v/X".

    In another example, the HTTPS request::

        GET /?q=1 HTTP/1.1
        Host: www.example.net:8080

    is represented by the base string URI: "https://www.example.net:8080/".

    .. _`section 3.4.1.2`: https://tools.ietf.org/html/rfc5849#section-3.4.1.2

    The host argument overrides the netloc part of the uri argument.
    """
    if not isinstance(uri, str):
        raise ValueError('uri must be a unicode object.')

    # FIXME: urlparse does not support unicode
    scheme, netloc, path, params, query, fragment = urlparse.urlparse(uri)

    # The scheme, authority, and path of the request resource URI `RFC3986`
    # are included by constructing an "http" or "https" URI representing
    # the request resource (without the query or fragment) as follows:
    #
    # .. _`RFC3986`: https://tools.ietf.org/html/rfc3986

    if not scheme or not netloc:
        raise ValueError('uri must include a scheme and netloc')

    # Per `RFC 2616 section 5.1.2`_:
    #
    # Note that the absolute path cannot be empty; if none is present in
    # the original URI, it MUST be given as "/" (the server root).
    #
    # .. _`RFC 2616 section 5.1.2`: https://tools.ietf.org/html/rfc2616#section-5.1.2
    if not path:
        path = '/'

    # 1.  The scheme and host MUST be in lowercase.
    scheme = scheme.lower()
    netloc = netloc.lower()

    # 2.  The host and port values MUST match the content of the HTTP
    #     request "Host" header field.
    if host is not None:
        netloc = host.lower()

    # 3.  The port MUST be included if it is not the default port for the
    #     scheme, and MUST be excluded if it is the default.  Specifically,
    #     the port MUST be excluded when making an HTTP request `RFC2616`_
    #     to port 80 or when making an HTTPS request `RFC2818`_ to port 443.
    #     All other non-default port numbers MUST be included.
    #
    # .. _`RFC2616`: https://tools.ietf.org/html/rfc2616
    # .. _`RFC2818`: https://tools.ietf.org/html/rfc2818
    default_ports = (
        ('http', '80'),
        ('https', '443'),
    )
    if ':' in netloc:
        host, port = netloc.split(':', 1)
        if (scheme, port) in default_ports:
            netloc = host

    v = urlparse.urlunparse((scheme, netloc, path, params, '', ''))

    # RFC 5849 does not specify which characters are encoded in the
    # "base string URI", nor how they are encoded - which is very bad, since
    # the signatures won't match if there are any differences. Fortunately,
    # most URIs only use characters that are clearly not encoded (e.g. digits
    # and A-Z, a-z), so have avoided any differences between implementations.
    #
    # The example from its section 3.4.1.2 illustrates that spaces in
    # the path are percent encoded. But it provides no guidance as to what other
    # characters (if any) must be encoded (nor how); nor if characters in the
    # other components are to be encoded or not.
    #
    # This implementation **assumes** that **only** the space is percent-encoded
    # and it is done to the entire value (not just to spaces in the path).
    #
    # This code may need to be changed if it is discovered that other characters
    # are expected to be encoded.
    #
    # Note: the "base string URI" returned by this function will be encoded
    # again before being concatenated into the "signature base string". So any
    # spaces in the URI will actually appear in the "signature base string"
    # as "%2520" (the "%20" further encoded according to section 3.6).

    return v.replace(' ', '%20')


# ** Request Parameters **
#
#    Per `section 3.4.1.3`_ of the spec.
#
#    In order to guarantee a consistent and reproducible representation of
#    the request parameters, the parameters are collected and decoded to
#    their original decoded form.  They are then sorted and encoded in a
#    particular manner that is often different from their original
#    encoding scheme, and concatenated into a single string.
#
# .. _`section 3.4.1.3`: https://tools.ietf.org/html/rfc5849#section-3.4.1.3

def collect_parameters(uri_query='', body=None, headers=None,
                       exclude_oauth_signature=True, with_realm=False):
    """**Parameter Sources**

    Parameters starting with `oauth_` will be unescaped.

    Body parameters must be supplied as a dict, a list of 2-tuples, or a
    formencoded query string.

    Headers must be supplied as a dict.

    Per `section 3.4.1.3.1`_ of the spec.

    For example, the HTTP request::

        POST /request?b5=%3D%253D&a3=a&c%40=&a2=r%20b HTTP/1.1
        Host: example.com
        Content-Type: application/x-www-form-urlencoded
        Authorization: OAuth realm="Example",
            oauth_consumer_key="9djdj82h48djs9d2",
            oauth_token="kkk9d7dh3k39sjv7",
            oauth_signature_method="HMAC-SHA1",
            oauth_timestamp="137131201",
            oauth_nonce="7d8f3e4a",
            oauth_signature="djosJKDKJSD8743243%2Fjdk33klY%3D"

        c2&a3=2+q

    contains the following (fully decoded) parameters used in the
    signature base sting::

        +------------------------+------------------+
        |          Name          |       Value      |
        +------------------------+------------------+
        |           b5           |       =%3D       |
        |           a3           |         a        |
        |           c@           |                  |
        |           a2           |        r b       |
        |   oauth_consumer_key   | 9djdj82h48djs9d2 |
        |       oauth_token      | kkk9d7dh3k39sjv7 |
        | oauth_signature_method |     HMAC-SHA1    |
        |     oauth_timestamp    |     137131201    |
        |       oauth_nonce      |     7d8f3e4a     |
        |           c2           |                  |
        |           a3           |        2 q       |
        +------------------------+------------------+

    Note that the value of "b5" is "=%3D" and not "==".  Both "c@" and
    "c2" have empty values.  While the encoding rules specified in this
    specification for the purpose of constructing the signature base
    string exclude the use of a "+" character (ASCII code 43) to
    represent an encoded space character (ASCII code 32), this practice
    is widely used in "application/x-www-form-urlencoded" encoded values,
    and MUST be properly decoded, as demonstrated by one of the "a3"
    parameter instances (the "a3" parameter is used twice in this
    request).

    .. _`section 3.4.1.3.1`: https://tools.ietf.org/html/rfc5849#section-3.4.1.3.1
    """
    if body is None:
        body = []
    headers = headers or {}
    params = []

    # The parameters from the following sources are collected into a single
    # list of name/value pairs:

    # *  The query component of the HTTP request URI as defined by
    #    `RFC3986, Section 3.4`_.  The query component is parsed into a list
    #    of name/value pairs by treating it as an
    #    "application/x-www-form-urlencoded" string, separating the names
    #    and values and decoding them as defined by
    #    `W3C.REC-html40-19980424`_, Section 17.13.4.
    #
    # .. _`RFC3986, Section 3.4`: https://tools.ietf.org/html/rfc3986#section-3.4
    # .. _`W3C.REC-html40-19980424`: https://tools.ietf.org/html/rfc5849#ref-W3C.REC-html40-19980424
    if uri_query:
        params.extend(urldecode(uri_query))

    # *  The OAuth HTTP "Authorization" header field (`Section 3.5.1`_) if
    #    present.  The header's content is parsed into a list of name/value
    #    pairs excluding the "realm" parameter if present.  The parameter
    #    values are decoded as defined by `Section 3.5.1`_.
    #
    # .. _`Section 3.5.1`: https://tools.ietf.org/html/rfc5849#section-3.5.1
    if headers:
        headers_lower = {k.lower(): v for k, v in headers.items()}
        authorization_header = headers_lower.get('authorization')
        if authorization_header is not None:
            params.extend([i for i in utils.parse_authorization_header(
                authorization_header) if with_realm or i[0] != 'realm'])

    # *  The HTTP request entity-body, but only if all of the following
    #    conditions are met:
    #     *  The entity-body is single-part.
    #
    #     *  The entity-body follows the encoding requirements of the
    #        "application/x-www-form-urlencoded" content-type as defined by
    #        `W3C.REC-html40-19980424`_.

    #     *  The HTTP request entity-header includes the "Content-Type"
    #        header field set to "application/x-www-form-urlencoded".
    #
    # .._`W3C.REC-html40-19980424`: https://tools.ietf.org/html/rfc5849#ref-W3C.REC-html40-19980424

    # TODO: enforce header param inclusion conditions
    bodyparams = extract_params(body) or []
    params.extend(bodyparams)

    # ensure all oauth params are unescaped
    unescaped_params = []
    for k, v in params:
        if k.startswith('oauth_'):
            v = utils.unescape(v)
        unescaped_params.append((k, v))

    # The "oauth_signature" parameter MUST be excluded from the signature
    # base string if present.
    if exclude_oauth_signature:
        unescaped_params = list(filter(lambda i: i[0] != 'oauth_signature',
                                       unescaped_params))

    return unescaped_params


def normalize_parameters(params):
    """**Parameters Normalization**
    Per `section 3.4.1.3.2`_ of the spec.

    For example, the list of parameters from the previous section would
    be normalized as follows:

    Encoded::

    +------------------------+------------------+
    |          Name          |       Value      |
    +------------------------+------------------+
    |           b5           |     %3D%253D     |
    |           a3           |         a        |
    |          c%40          |                  |
    |           a2           |       r%20b      |
    |   oauth_consumer_key   | 9djdj82h48djs9d2 |
    |       oauth_token      | kkk9d7dh3k39sjv7 |
    | oauth_signature_method |     HMAC-SHA1    |
    |     oauth_timestamp    |     137131201    |
    |       oauth_nonce      |     7d8f3e4a     |
    |           c2           |                  |
    |           a3           |       2%20q      |
    +------------------------+------------------+

    Sorted::

    +------------------------+------------------+
    |          Name          |       Value      |
    +------------------------+------------------+
    |           a2           |       r%20b      |
    |           a3           |       2%20q      |
    |           a3           |         a        |
    |           b5           |     %3D%253D     |
    |          c%40          |                  |
    |           c2           |                  |
    |   oauth_consumer_key   | 9djdj82h48djs9d2 |
    |       oauth_nonce      |     7d8f3e4a     |
    | oauth_signature_method |     HMAC-SHA1    |
    |     oauth_timestamp    |     137131201    |
    |       oauth_token      | kkk9d7dh3k39sjv7 |
    +------------------------+------------------+

    Concatenated Pairs::

    +-------------------------------------+
    |              Name=Value             |
    +-------------------------------------+
    |               a2=r%20b              |
    |               a3=2%20q              |
    |                 a3=a                |
    |             b5=%3D%253D             |
    |                c%40=                |
    |                 c2=                 |
    | oauth_consumer_key=9djdj82h48djs9d2 |
    |         oauth_nonce=7d8f3e4a        |
    |   oauth_signature_method=HMAC-SHA1  |
    |      oauth_timestamp=137131201      |
    |     oauth_token=kkk9d7dh3k39sjv7    |
    +-------------------------------------+

    and concatenated together into a single string (line breaks are for
    display purposes only)::

        a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9dj
        dj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1
        &oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7

    .. _`section 3.4.1.3.2`: https://tools.ietf.org/html/rfc5849#section-3.4.1.3.2
    """

    # The parameters collected in `Section 3.4.1.3`_ are normalized into a
    # single string as follows:
    #
    # .. _`Section 3.4.1.3`: https://tools.ietf.org/html/rfc5849#section-3.4.1.3

    # 1.  First, the name and value of each parameter are encoded
    #     (`Section 3.6`_).
    #
    # .. _`Section 3.6`: https://tools.ietf.org/html/rfc5849#section-3.6
    key_values = [(utils.escape(k), utils.escape(v)) for k, v in params]

    # 2.  The parameters are sorted by name, using ascending byte value
    #     ordering.  If two or more parameters share the same name, they
    #     are sorted by their value.
    key_values.sort()

    # 3.  The name of each parameter is concatenated to its corresponding
    #     value using an "=" character (ASCII code 61) as a separator, even
    #     if the value is empty.
    parameter_parts = ['{}={}'.format(k, v) for k, v in key_values]

    # 4.  The sorted name/value pairs are concatenated together into a
    #     single string by using an "&" character (ASCII code 38) as
    #     separator.
    return '&'.join(parameter_parts)


# ================================================================
# Common functions for HMAC-based signature methods

def _hmac_sign(sig_base_str, hash_alg, client_secret, resource_owner_secret):
    """
    **HMAC-SHA256**

    The "HMAC-SHA256" signature method uses the HMAC-SHA256 signature
    algorithm as defined in `RFC4634`_::

        digest = HMAC-SHA256 (key, text)

    Per `section 3.4.2`_ of the spec.

    .. _`RFC4634`: https://tools.ietf.org/html/rfc4634
    .. _`section 3.4.2`: https://tools.ietf.org/html/rfc5849#section-3.4.2
    """

    # The HMAC-SHA256 function variables are used in following way:

    # text is set to the value of the signature base string from
    # `Section 3.4.1.1`_.
    #
    # .. _`Section 3.4.1.1`: https://tools.ietf.org/html/rfc5849#section-3.4.1.1
    text = sig_base_str

    # key is set to the concatenated values of:
    # 1.  The client shared-secret, after being encoded (`Section 3.6`_).
    #
    # .. _`Section 3.6`: https://tools.ietf.org/html/rfc5849#section-3.6
    key = utils.escape(client_secret or '')

    # 2.  An "&" character (ASCII code 38), which MUST be included
    #     even when either secret is empty.
    key += '&'

    # 3.  The token shared-secret, after being encoded (`Section 3.6`_).
    #
    # .. _`Section 3.6`: https://tools.ietf.org/html/rfc5849#section-3.6
    key += utils.escape(resource_owner_secret or '')

    # FIXME: HMAC does not support unicode!
    key_utf8 = key.encode('utf-8')
    text_utf8 = text.encode('utf-8')
    signature = hmac.new(key_utf8, text_utf8, hash_alg)

    # digest  is used to set the value of the "oauth_signature" protocol
    #         parameter, after the result octet string is base64-encoded
    #         per `RFC2045, Section 6.8`.
    #
    # .. _`RFC2045, Section 6.8`: https://tools.ietf.org/html/rfc2045#section-6.8
    return binascii.b2a_base64(signature.digest())[:-1].decode('utf-8')


def _hmac_verify(request, hash_alg,
                 client_secret=None, resource_owner_secret=None):
    """Verify a HMAC-SHA1 signature.

    Per `section 3.4`_ of the spec.

    .. _`section 3.4`: https://tools.ietf.org/html/rfc5849#section-3.4

    To satisfy `RFC2616 section 5.2`_ item 1, the request argument's uri
    attribute MUST be an absolute URI whose netloc part identifies the
    origin server or gateway on which the resource resides. Any Host
    item of the request argument's headers dict attribute will be
    ignored.

    .. _`RFC2616 section 5.2`: https://tools.ietf.org/html/rfc2616#section-5.2

    """
    norm_params = normalize_parameters(request.params)
    bs_uri = base_string_uri(request.uri)
    sig_base_str = signature_base_string(request.http_method, bs_uri,
                                         norm_params)
    signature = _hmac_sign(sig_base_str, hash_alg,
                           client_secret, resource_owner_secret)
    match = safe_string_equals(signature, request.signature)
    if not match:
        log.debug('Verify HMAC failed: signature base string: %s', sig_base_str)
    return match


# ================================================================
# HMAC-SHA1
#
# Standard OAuth 1.0a signature method.

def sign_hmac_sha1_with_client(sig_base_str, client):
    return _hmac_sign(sig_base_str, hashlib.sha1,
                      client.client_secret, client.resource_owner_secret)


def verify_hmac_sha1(request, client_secret=None, resource_owner_secret=None):
    return _hmac_verify(request, hashlib.sha1,
                        client_secret, resource_owner_secret)


# ================================================================
# HMAC-SHA256
#
# Note: this signature method is not defined by OAuth 1.0a.

def sign_hmac_sha256_with_client(sig_base_str, client):
    return _hmac_sign(sig_base_str, hashlib.sha256,
                      client.client_secret, client.resource_owner_secret)


def verify_hmac_sha256(request, client_secret=None, resource_owner_secret=None):
    return _hmac_verify(request, hashlib.sha256,
                        client_secret, resource_owner_secret)


# ================================================================
# HMAC-SHA512
#
# Note: this signature method is not defined by OAuth 1.0a.

def sign_hmac_sha512_with_client(sig_base_str, client):
    return _hmac_sign(sig_base_str, hashlib.sha512,
                      client.client_secret, client.resource_owner_secret)


def verify_hmac_sha512(request, client_secret=None, resource_owner_secret=None):
    return _hmac_verify(request, hashlib.sha512,
                        client_secret, resource_owner_secret)


# ================================================================
# Common functions for RSA-based signature methods

def _prepare_key_plus(alg, keystr):
    """
    Prepare a PEM encoded key (public or private), by invoking the `prepare_key`
    method on alg with the keystr.

    The keystr should be a string or bytes.  If the keystr is bytes, it is
    decoded as UTF-8 before being passed to prepare_key. Otherwise, it
    is passed directly.
    """
    if isinstance(keystr, bytes):
        keystr = keystr.decode('utf-8')
    return alg.prepare_key(keystr)


def _rsa_sign(sig_base_str, alg, rsa_private_key):
    """
    Calculate the signature for an RSA-based signature method.

    The ``alg`` is used to calculate the digest over the signature base string.
    For the "RSA_SHA1" signature method, the alg must be SHA-1. While OAuth 1.0a
    only defines the RSA-SHA1 signature method, this function can be used for
    other non-standard signature methods that only differ from RSA-SHA1 by the
    digest algorithm.

    Signing for the RSA-SHA1 signature method is defined in
    `section 3.4.3`_ of RFC 5849.

    The RSASSA-PKCS1-v1_5 signature algorithm used defined by
    `RFC3447, Section 8.2`_ (also known as PKCS#1), with the `alg` as the
    hash function for EMSA-PKCS1-v1_5.  To
    use this method, the client MUST have established client credentials
    with the server that included its RSA public key (in a manner that is
    beyond the scope of this specification).

    .. _`section 3.4.3`: https://tools.ietf.org/html/rfc5849#section-3.4.3
    .. _`RFC3447, Section 8.2`: https://tools.ietf.org/html/rfc3447#section-8.2
    """

    if not rsa_private_key:
        raise ValueError('rsa_private_key required for RSA with ' +
                         alg.hash_alg.name + ' signature method')

    # Convert the "signature base string" into a sequence of bytes (M)
    #
    # The signature base string only contain printable US-ASCII characters.
    # The ``encode`` method with the default "strict" error handling will raise
    # a ``UnicodeError`` if it can't encode the value. So using "ascii" will
    # always work unless the signature base string was incorrectly produced.

    assert(isinstance(sig_base_str, str))
    m = sig_base_str.encode('ascii')

    # Perform signing: S = RSASSA-PKCS1-V1_5-SIGN (K, M)

    key = _prepare_key_plus(alg, rsa_private_key)
    s = alg.sign(m, key)

    # base64-encoded per RFC2045 section 6.8.
    #
    # 1. While b2a_base64 implements base64 defined by RFC 3548. As used here,
    #    it is the same as base64 defined by RFC 2045.
    # 2. b2a_base64 includes a "\n" at the end of its result ([:-1] removes it)
    # 3. b2a_base64 produces a binary string. Use decode to produce a str.
    #    It should only contain only printable US-ASCII characters.

    return binascii.b2a_base64(s)[:-1].decode('ascii')


def _rsa_verify(request, alg, rsa_public_key):
    """
    Verify a base64 encoded signature for a RSA-based signature method.

    The ``alg`` is used to calculate the digest over the signature base string.
    For the "RSA_SHA1" signature method, the alg must be SHA-1. While OAuth 1.0a
    only defines the RSA-SHA1 signature method, this function can be used for
    other non-standard signature methods that only differ from RSA-SHA1 by the
    digest algorithm.

    Verification for the RSA-SHA1 signature method is defined in
    `section 3.4.3`_ of RFC 5849.

    .. _`section 3.4.3`: https://tools.ietf.org/html/rfc5849#section-3.4.3

        To satisfy `RFC2616 section 5.2`_ item 1, the request argument's uri
        attribute MUST be an absolute URI whose netloc part identifies the
        origin server or gateway on which the resource resides. Any Host
        item of the request argument's headers dict attribute will be
        ignored.

        .. _`RFC2616 section 5.2`: https://tools.ietf.org/html/rfc2616#section-5.2
    """

    # Calculate the *signature base string* of the actual received request
    #
    # The signature base string only contain printable US-ASCII characters.
    # The ``encode`` method with the default "strict" error handling will raise
    # a ``UnicodeError`` if it can't encode the value. So using "ascii" will
    # always work unless the signature base string was incorrectly produced.

    norm_params = normalize_parameters(request.params)
    bs_uri = base_string_uri(request.uri)
    sig_base_str = signature_base_string(
        request.http_method, bs_uri, norm_params).encode('ascii')

    try:
        # Obtain the signature that was received in the request

        sig = binascii.a2b_base64(request.signature.encode('ascii'))

        # Verify the received signature was produced by the private key
        # corresponding to the `rsa_public_key`, signing exact same
        # *signature base string*.
        #
        #     RSASSA-PKCS1-V1_5-VERIFY ((n, e), M, S)

        key = _prepare_key_plus(alg, rsa_public_key)
        verify_ok = alg.verify(sig_base_str, key, sig)

        if not verify_ok:
            log.debug('Verify failed: RSA with ' + alg.hash_alg.name +
                      ': signature base string=%s' + sig_base_str)
        return verify_ok

    except UnicodeError:
        # A properly encoded signature will only contain printable US-ASCII
        # characters. The ``encode`` method with the default "strict" error
        # handling will raise a ``UnicodeError`` if it can't decode the value.
        # So using "ascii" will work with all valid signatures. But an
        # incorrectly or maliciously produced signature could contain other
        # bytes.
        #
        # This implementation treats that situation as equivalent to the
        # signature verification having failed.
        #
        # Note: simply changing the encode to use 'utf-8' will not remove this
        # case, since an incorrect or malicious request can contain bytes which
        # are invalid as UTF-8.
        return False


# ================================================================
# RSA-SHA1
#
# Standard OAuth 1.0a signature method.

_jwtrs1 = None


def _jwt_rs1_signing_algorithm():
    global _jwtrs1
    if _jwtrs1 is None:
        # PyJWT has some nice pycrypto/cryptography abstractions
        import jwt.algorithms as jwtalgo
        _jwtrs1 = jwtalgo.RSAAlgorithm(jwtalgo.hashes.SHA1)
    return _jwtrs1


def sign_rsa_sha1_with_client(sig_base_str, client):
    return _rsa_sign(sig_base_str, _jwt_rs1_signing_algorithm(),
                     client.rsa_key)


def verify_rsa_sha1(request, rsa_public_key):
    return _rsa_verify(request, _jwt_rs1_signing_algorithm(), rsa_public_key)


# ================================================================
# RSA-SHA256
#
# Note: this signature method is not defined by OAuth 1.0a.

_jwtrs256 = None


def _jwt_rs256_signing_algorithm():
    global _jwtrs256
    if _jwtrs256 is None:
        import jwt.algorithms as jwtalgo
        _jwtrs256 = jwtalgo.RSAAlgorithm(jwtalgo.hashes.SHA256)
    return _jwtrs256


def sign_rsa_sha256_with_client(sig_base_str, client):
    return _rsa_sign(sig_base_str, _jwt_rs256_signing_algorithm(),
                     client.rsa_key)


def verify_rsa_sha256(request, rsa_public_key):
    return _rsa_verify(request, _jwt_rs256_signing_algorithm(), rsa_public_key)


# ================================================================
# RSA-SHA512
#
# Note: this signature method is not defined by OAuth 1.0a.

_jwtrs512 = None


def _jwt_rs512_signing_algorithm():
    global _jwtrs512
    if _jwtrs512 is None:
        import jwt.algorithms as jwtalgo
        _jwtrs512 = jwtalgo.RSAAlgorithm(jwtalgo.hashes.SHA512)
    return _jwtrs512


def sign_rsa_sha512_with_client(sig_base_str, client):
    return _rsa_sign(sig_base_str, _jwt_rs512_signing_algorithm(),
                     client.rsa_key)


def verify_rsa_sha512(request, rsa_public_key):
    return _rsa_verify(request, _jwt_rs512_signing_algorithm(), rsa_public_key)


# ================================================================
# PLAINTEXT
#
# Standard OAuth 1.0a signature method.

def sign_plaintext_with_client(_signature_base_string, client):
    # _signature_base_string is not used because the signature with PLAINTEXT
    # is just the secret: it isn't a real signature.
    return sign_plaintext(client.client_secret, client.resource_owner_secret)


def sign_plaintext(client_secret, resource_owner_secret):
    """Sign a request using plaintext.

    Per `section 3.4.4`_ of the spec.

    The "PLAINTEXT" method does not employ a signature algorithm.  It
    MUST be used with a transport-layer mechanism such as TLS or SSL (or
    sent over a secure channel with equivalent protections).  It does not
    utilize the signature base string or the "oauth_timestamp" and
    "oauth_nonce" parameters.

    .. _`section 3.4.4`: https://tools.ietf.org/html/rfc5849#section-3.4.4

    """

    # The "oauth_signature" protocol parameter is set to the concatenated
    # value of:

    # 1.  The client shared-secret, after being encoded (`Section 3.6`_).
    #
    # .. _`Section 3.6`: https://tools.ietf.org/html/rfc5849#section-3.6
    signature = utils.escape(client_secret or '')

    # 2.  An "&" character (ASCII code 38), which MUST be included even
    #     when either secret is empty.
    signature += '&'

    # 3.  The token shared-secret, after being encoded (`Section 3.6`_).
    #
    # .. _`Section 3.6`: https://tools.ietf.org/html/rfc5849#section-3.6
    signature += utils.escape(resource_owner_secret or '')

    return signature


def verify_plaintext(request, client_secret=None, resource_owner_secret=None):
    """Verify a PLAINTEXT signature.

    Per `section 3.4`_ of the spec.

    .. _`section 3.4`: https://tools.ietf.org/html/rfc5849#section-3.4
    """
    signature = sign_plaintext(client_secret, resource_owner_secret)
    match = safe_string_equals(signature, request.signature)
    if not match:
        log.debug('Verify PLAINTEXT failed')
    return match
