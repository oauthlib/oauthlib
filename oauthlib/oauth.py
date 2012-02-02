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

def order_params(target):
    """Order OAuth parameters first
    
    :param target: A method with the first arg being params.
    """
    def wrapper(params, *args, **kwargs):
        params = order_parameters(params)
        return target(params, *args, **kwargs)
    
    wrapper.__doc__ = target.__doc__ 
    return wrapper

def filter_oauth(target):
    """Removes all non oauth parameters
    
    :param target: A method with the first arg being params.
    """

    def wrapper(params, *args, **kwargs):
        # Convert dictionaries to list of tuples
        if isinstance(params, dict):
            filtered = [(k,v) for k,v in params.items() if k.startswith("oauth_")]
        else:
            filtered = [(k,v) for k,v in params if k.startswith("oauth_")]
        return target(filtered, *args, **kwargs)

    wrapper.__doc__ = target.__doc__ 
    return wrapper

#####################
# OAuth methods
#####################

def escape(s):
    """Escape a string in an OAuth-compatible fashion.

    Per `section 3.6`_ of the spec.

    :param s: The string to be escaped.
    :return: An url encoded string.

    .. _`section 3.6`: http://tools.ietf.org/html/rfc5849#section-3.6

    """
    return urllib.quote(s.encode('utf-8'), safe='~')


def utf8_str(s):
    """Convert unicode to UTF-8.
       
    :param s: The string to convert.
    :return: An UTF-8 string.
    """
    if isinstance(s, unicode):
        return s.encode("utf-8")
    else:
        return str(s)


def generate_timestamp():
    """Get seconds since epoch (UTC).
    
    :return: Seconds since epoch.
    """
    return str(int(time.time()))


def generate_nonce():
    """Generate pseudorandom nonce that is unlikely to repeat."""
    return str(getrandbits(64)) + generate_timestamp()


def generate_params(client_key=None, 
                    access_token=None, 
                    request_token=None,
                    signature_method="HMAC-SHA1",
                    callback=None,
                    verifier=None):
    """Generates the requisite parameters for a valid OAuth request.

    All values will be escaped/url encoded.

    The nonce, timestamp and version parameters will be generated.

    :param client_key: (Optional) Client/Consumer key.
    :param access_token: (Optional) Access token (to access resources).
    :param request_token: (Optional) Request token (to obtain access token).
    :param signature_method: (Optional) One of HMAC-SHA1, RSA-SHA1 or PLAINTEXT.
    :param callback: (Optional) The url to redirect to after authorization.
    :param verifier: (Optional) Used when obtaining access tokens.
    :return: List of tuples [(parameter, value),..]
    """
    params = {
       'oauth_nonce': generate_nonce(),
       'oauth_timestamp': generate_timestamp(),
       'oauth_version': '1.0',
       'oauth_signature_method': signature_method,
    }
    
    if client_key:
        params['oauth_consumer_key'] = escape(client_key)

    if request_token:
        params["oauth_token"] = escape(request_token)

    if access_token:
        params["oauth_token"] = escape(access_token)
        
    if callback:
        params["oauth_callback"] = escape(callback)

    if verifier:
        params["oauth_verifier"] = escape(verifier)

    return params.items()


def normalize_http_method(method):
    """Uppercases the HTTP method.

    Per `section 3.4.1.1`_ of the spec.

    :param method: The HTTP request method.
    :return: Uppercased HTTP request method.

    .. _`section 3.4.1.1`: http://tools.ietf.org/html/rfc5849#section-3.4.1.1

    """
    return method.upper()


def normalize_base_string_uri(uri):
    """Prepares the base string URI.

    Parses the URL and rebuilds it to be scheme://host/path. The normalized
    return value is already escaped.

    :param uri: The URI to be normalized.
    :return: A normalized and lowercased uri with default port numbers removed. 

    Per `section 3.4.1.2`_ of the spec.

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

    Per `section 3.4.1.3`_ of the spec.

    :param params: A dictionary or list of parameters to be normalized.
    :return: A list of tuples containing sorted and normalized parameters. 

    .. _`section 3.4.1.3`: http://tools.ietf.org/html/rfc5849#section-3.4.1.3

    """
    # Escape key values before sorting.
    key_values = []
    for k, v in params:
        # Exclude the signature if it exists.
        if not k == "oauth_signature":
            key_values.append((escape(utf8_str(k)), escape(utf8_str(v))))

    # Sort lexicographically, first after key, then after value.
    key_values.sort()

    # Combine key value pairs into a string and return.
    return escape('&'.join(['{0}={1}'.format(k, v) for k, v in key_values]))


def order_parameters(params):
    """Order the parameters with OAuth ones first

    Per `section 3.5`_ of the spec.

    :param params: A dictionary or list of parameters to be sorted.
    :return: A list of tuples with OAuth parameters first.

    .. _`section 3.5`: http://tools.ietf.org/html/rfc5849#section-3.5
    """
    # Convert dictionaries to list of tuples
    if isinstance(params, dict):
        params = params.items()

    ordered = []
    for k,v in params:
        if k.startswith("oauth_"):
            ordered.insert(0, (k, v))
        else:
            ordered.append((k, v))
        
    return ordered


def prepare_hmac_key(client_secret=None, access_secret=None):
    """Prepares the signing key for HMAC-SHA1.

    Per `section 3.4.2`_ of the spec.

    :param client_secret: (Optional) The shared consumer secret.
    :param access_secret: (Optional) Token secret or access secret.
    :return: A string of the concatenated secrets.

    .. _`section 3.4.2`: http://tools.ietf.org/html/rfc5849#section-3.4.2

    """
    return '{0}&{1}'.format(
        escape(client_secret or ''),
        escape(access_secret or ''))


def prepare_base_string(method, uri, params):
    """Prepare a signature base string.

    Per `section 3.4.1`_ of the spec.

    :param method: The HTTP request method.
    :param uri: The request URI (may contain query parameters).
    :param params: OAuth parameters and data (i.e. POST data).
    :return: A base string as per `section 3.4.1`_ of the spec. 

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


def sign_hmac(method, url, params, client_secret=None, access_secret=None):
    """Sign a request using HMAC-SHA1.

    Per `section 3.4.2`_ of the spec.

    :param method: The HTTP request method.
    :param uri: The request URI (may contain query parameters).
    :param params: OAuth parameters and data (i.e. POST data).
    :param client_secret: (Optional) Consumer shared secret.
    :param access_secret: (Optional) Token secret or access secret.
    :return: A HMAC-SHA1 signature per `section 3.4.2`_ of the spec.

    .. _`section 3.4.2`: http://tools.ietf.org/html/rfc5849#section-3.4.2

    """
    base_string = prepare_base_string(method, url, params)
    key = prepare_hmac_key(client_secret, access_secret)
    signature = hmac.new(key, base_string, hashlib.sha1)
    return escape(binascii.b2a_base64(signature.digest())[:-1])

def sign_plain(client_secret, access_secret):
    """Sign a request using plaintext.

    Per `section 3.4.4`_ of the spec.

    :param client_secret: (Optional) Consumer shared secret.
    :param access_secret: (Optional) Token secret or access secret.
    :return: A PLAINTEXT signature per `section 3.4.4`_ of the spec.

    .. _`section 3.4.4`: http://tools.ietf.org/html/rfc5849#section-3.4.4

    """
    # HMAC-SHA1 concatenates the secrets in the same way a plain signature
    # is crafted.
    return prepare_hmac_key(client_secret, access_secret)

def sign_rsa(method, url, params, private_rsa):
    """Sign a request using RSASSA-PKCS #1 v1.5.

    Per `section 3.4.3`_ of the spec.

    Note this method requires the PyCrypto library.

    :param method: The HTTP request method.
    :param uri: The request URI (may contain query parameters).
    :param params: OAuth parameters and data (i.e. POST data).
    :param private_rsa: Private RSA key (string).
    :return: A RSA-SHA1 signature per `section 3.4.3`_ of the spec.

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

    Note this method requires the PyCrypto library.

    :param method: The HTTP request method.
    :param uri: The request URI (may contain query parameters).
    :param params: OAuth parameters and data (i.e. POST data).
    :param public_rsa: Public RSA key (string).
    :return: True or False.

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

@filter_oauth
def prepare_authorization_header(params, realm=None):
    """Prepare the Authorization header.

    Per `section 3.5.1`_ of the spec.

    :param params: OAuth parameters, non OAuth parameters will be removed.
    :param realm: OAuth realm, often referred to as scope. 
    :return: An OAuth Authorization header as per `section 3.5.1`_.

    .. _`section 3.5.1`: http://tools.ietf.org/html/rfc5849#section-3.5.1

    """
    if realm:
        params.insert(0, ("realm", realm))
    
    # Only oauth_ and realm parameters allowed
    return 'OAuth {params}'.format(params=', '.join(
           ['{0}="{1}"'.format(k, v) for k, v in params])) 

@order_params
def prepare_form_encoded_body(params):
    """Prepare the Form-Encoded Body.

    Per `section 3.5.2`_ of the spec.

    :param params: OAuth parameters and data (i.e. POST data).
    :return: An OAuth Form Encoded body as per `section 3.5.2`_.

    .. _`section 3.5.2`: http://tools.ietf.org/html/rfc5849#section-3.5.2

    """
    return '&'.join(['{0}={1}'.format(k, v) for k, v in params])

@order_params
def prepare_request_uri_query(params, url):
    """Prepare the Request URI Query.

    Per `section 3.5.3`_ of the spec.

    :param params: OAuth parameters and data (i.e. POST data).
    :param url: The request url, may NOT include query parameters.
    :return: An OAuth Request URI query as per `section 3.5.3`_.

    .. _`section 3.5.3`: http://tools.ietf.org/html/rfc5849#section-3.5.3

    """
    return '{url}?{params}'.format(
        url=url, params='&'.join(
            ['{0}={1}'.format(k, v) for k, v in params]))

 
