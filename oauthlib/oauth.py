# -*- coding: utf-8 -*-

"""
oauthlib.oauth
~~~~~~~~~~~~~~

This module is a generic implementation of various logic needed
for signing OAuth requests.
"""

import time
import hashlib
from random import getrandbits
import urllib
import hmac
import binascii
from urlparse import urlparse

SIGNATURE_HMAC = "HMAC-SHA1"
SIGNATURE_RSA = "RSA-SHA1"
SIGNATURE_PLAINTEXT = "PLAINTEXT"


def escape(s):
    """Escape a string in an OAuth-compatible fashion.

    Per `section 3.6`_ of the spec.

    .. _`section 3.6`: http://tools.ietf.org/html/rfc5849#section-3.6

    """
    return urllib.quote(s.encode('utf-8'), safe='~')


def utf8_str(s):
    """Convert unicode to utf-8."""
    if isinstance(s, unicode):
        return s.encode("utf-8")
    else:
        return str(s)


def generate_timestamp():
    """Get seconds since epoch (UTC)."""
    return str(int(time.time()))


def generate_nonce():
    """Generate pseudorandom nonce that is unlikely to repeat."""
    return str(getrandbits(64)) + generate_timestamp()


def generate_params(client_key, access_token, signature_method):
    """Generates the requisite parameters for a valid OAuth request."""
    params = {
       'oauth_consumer_key': client_key,
       'oauth_nonce': generate_nonce(),
       'oauth_signature_method': signature_method,
       'oauth_token': access_token,
       'oauth_timestamp': generate_timestamp(),
       'oauth_version': '1.0',
    }
    return params


def normalize_http_method(method):
    """Uppercases the HTTP method.

    Per `section 3.4.1.1` of the spec.

    .. _`section 3.4.1.1`: http://tools.ietf.org/html/rfc5849#section-3.4.1.1

    """
    return method.upper()


def normalize_base_string_uri(uri):
    """Prepares the base string URI.

    Parses the URL and rebuilds it to be scheme://host/path. The normalized
    return value is already escaped.

    Per `section 3.4.1.2` of the spec.

    .. _`section 3.4.1.2`: http://tools.ietf.org/html/rfc5849#section-3.4.1.2

    """
    parts = urlparse(uri)
    scheme, netloc, path = parts[:3]
    # Exclude default port numbers.
    if scheme == 'http' and netloc[-3:] == ':80':
        netloc = netloc[:-3]
    elif scheme == 'https' and netloc[-4:] == ':443':
        netloc = netloc[:-4]
    return escape('{0}://{1}{2}'.format(scheme, netloc.lower(), path))


def normalize_parameters(params):
    """Prepares the request parameters.

    Per `section 3.4.1.3` of the spec.

    .. _`section 3.4.1.3`: http://tools.ietf.org/html/rfc5849#section-3.4.1.3

    """
    try:
        # Exclude the signature if it exists.
        del params['oauth_signature']
    except:
        pass

    # Escape key values before sorting.
    key_values = []
    for k, v in params:
        key_values.append((escape(utf8_str(k)), escape(utf8_str(v))))

    # Sort lexicographically, first after key, then after value.
    key_values.sort()

    # Combine key value pairs into a string and return.
    return escape('&'.join(['{0}={1}'.format(k, v) for k, v in key_values]))


def order_parameters(params):
    """Order the parameters with OAuth ones first

    Per `section 3.5.` of the spec.

    .. _`section 3.5`: http://tools.ietf.org/html/rfc5849#section-3.5
    """
    pdict = dict(params)
    param_order = [ "oauth_consumer_key",
                    "oauth_token",
                    "oauth_signature_method",
                    "oauth_signature",
                    "oauth_timestamp",
                    "oauth_nonce",
                    "oauth_version" ]
    ordered_params = []
    for param in param_order:
        ordered_params.append((param, pdict[param]))
    
    for k,v in params:
        if not k in param_order:
            ordered_params.append((k, v))

    return ordered_params


def prepare_hmac_key(client_secret, access_secret=None):
    """Prepares the signing key for HMAC-SHA1.

    Per `section 3.4.2`_ of the spec.

    .. _`section 3.4.2`: http://tools.ietf.org/html/rfc5849#section-3.4.2

    """
    return '{0}&{1}'.format(
        escape(client_secret or ''),
        escape(access_secret or ''))


def prepare_base_string(method, uri, params):
    """Prepare a signature base string.

    Per `section 3.4.1`_ of the spec.

    .. _`section 3.4.1`: http://tools.ietf.org/html/rfc5849#section-3.4.1

    """
    # Convert dictionaries to list of tuples
    if isinstance(params, dict):
        params = params.items()

    # Add uri query components to parameters as per 3.4.1.3.1
    for qc in urlparse(uri).query.split("&"):
        if "=" in qc:
            k, v = qc.split("=")
            k, v = urllib.unquote(k), urllib.unquote(v) 
            params.append((k,v))

    return "{method}&{uri}&{params}".format(
        method=normalize_http_method(method),
        uri=normalize_base_string_uri(uri),
        params=normalize_parameters(params))


def sign_hmac(method, url, params, client_secret, access_secret):
    """Sign a request using HMAC-SHA1.

    Per `section 3.4.2`_ of the spec.

    .. _`section 3.4.2`: http://tools.ietf.org/html/rfc5849#section-3.4.2

    """
    base_string = prepare_base_string(method, url, params)
    key = prepare_hmac_key(client_secret, access_secret)
    signature = hmac.new(key, base_string, hashlib.sha1)
    return escape(binascii.b2a_base64(signature.digest())[:-1])

def sign_plain(client_secret, access_secret):
    """Sign a request using plaintext.

    Per `section 3.4.4`_ of the spec.

    .. _`section 3.4.4`: http://tools.ietf.org/html/rfc5849#section-3.4.4

    """
    # HMAC-SHA1 concatenates the secrets in the same way a plain signature
    # is crafted.
    return prepare_hmac_key(client_secret, access_secret)

def sign_rsa(method, url, params, private_rsa):
    """Sign a request using RSASSA-PKCS #1 v1.5.

    Per `section 3.4.3`_ of the spec.

    .. _`section 3.4.3`: http://tools.ietf.org/html/rfc5849#section-3.4.3

    """
    from Crypto.PublicKey import RSA
    from Crypto.Signature import PKCS1_v1_5
    from Crypto.Hash import SHA
    key = RSA.importKey(private_rsa)
    message = prepare_base_string(method, url, params)
    h = SHA.new(message)    
    p = PKCS1_v1_5.new(key)
    return escape(binascii.b2a_base64(p.sign(h))[:-1])

def verify_rsa(method, url, params, public_rsa, signature):
    """Verify a RSASSA-PKCS #1 v1.5 base64 encoded signature.

    Per `section 3.4.3`_ of the spec.

    .. _`section 3.4.3`: http://tools.ietf.org/html/rfc5849#section-3.4.3

    """
    from Crypto.PublicKey import RSA
    from Crypto.Signature import PKCS1_v1_5
    from Crypto.Hash import SHA
    key = RSA.importKey(public_rsa)
    message = prepare_base_string(method, url, params)
    h = SHA.new(message)
    p = PKCS1_v1_5.new(key)
    signature = binascii.a2b_base64(urllib.unquote(signature))
    return p.verify(h, signature)

def prepare_authorization_header(params, realm=None):
    """Prepare the authorization header.

    Per `section 3.5.1`_ of the spec.

    .. _`section 3.5.1`: http://tools.ietf.org/html/rfc5849#section-3.5.1

    """
    # Convert dictionaries to list of tuples
    if isinstance(params, dict):
        params = params.items()

    params = order_parameters(params)
    realm = 'realm="{realm}"'.format(realm=realm) if realm else ""

    return 'OAuth {realm}, {params}'.format(
        realm=realm, params=', '.join(
            ['{0}="{1}"'.format(k, v) for k, v in params]))
