# -*- coding: utf-8 -*-

"""
oauthlib.oauth
~~~~~~~~~~~~~~

This module is a generic implementation of various logic needed
for signing OAuth requests.
"""

import time, string, urllib, hashlib, hmac, binascii
from random import choice, getrandbits
from urlparse import urlparse, urlunparse, parse_qsl
from warnings import warn
from itertools import chain

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
        isOAuth = lambda kv: kv[0].startswith("oauth_")
        if isinstance(params, dict):
           return target(filter(isOAuth, params.items()), *args, **kwargs)
        else:
           return target(filter(isOAuth, params), *args, **kwargs)

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

def generate_token(length=20, chars=string.ascii_letters + string.digits):
    """Generates a generic OAuth token
    
    Credit to Ignacio Vazquez-Abrams for his excellent `Stackoverflow answer`_

    .. _`Stackoverflow answer` : http://stackoverflow.com/questions/2257441/
        python-random-string-generation-with-upper-case-letters-and-digits

    :param length: Token string length (default 20)
    :param chars: The charactes used to populate the token string
    :return: A length sized string of random characters
    """
    return ''.join(choice(chars) for x in range(length))

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
    # Escape key values before sorting (remove signature if present).
    key_values = [(escape(k), escape(v)) for k, v in params 
                                         if not k == "oauth_signature"]

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

    # Extract uri query components to parameters as per 3.4.1.3.1
    query = [(k, v) for k, v in parse_qsl(urlparse(uri).query, True)]

    return "{method}&{uri}&{params}".format(
        method=normalize_http_method(method),
        uri=normalize_base_string_uri(uri),
        params=normalize_parameters(chain(params, query)))


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
    return escape(prepare_hmac_key(client_secret, access_secret))

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
    # Realm should always be the first parameter
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
    :param url: The request url. Query components will be removed.
    :return: An OAuth Request URI query as per `section 3.5.3`_.

    .. _`section 3.5.3`: http://tools.ietf.org/html/rfc5849#section-3.5.3

    """
    # Add params to the existing set of query components
    sch, net, path, par, query, fra = urlparse(url)
    for k,v in parse_qsl(query, True):
        params.append((escape(k), escape(v)))
    query = "&".join(['{0}={1}'.format(k, v) for k,v in params])
    return urlunparse((sch, net, path, par, query, fra))


##################################################
# Convenience class for working with OAuth methods
##################################################

class OAuthError(Exception):
    pass

class OAuth(object):

    """Valid Signature Methods in OAuth 1.0"""
    SIG_METHODS = ("HMAC-SHA1", "RSA-SHA1", "PLAINTEXT")

    def __init__(self, 
        client_key=None,
        client_secret=None,
        request_token=None,
        access_token=None,
        token_secret=None,
        rsa_key=None,
        callback=None,
        signature_method="HMAC-SHA1",
        verifier=None):
        """Constructs an :class:`OAuth <OAuth>` object.
        
        :param client_key: The client identifier, also known as consumer key.
        :param client_secret: The client shared secret, or consumer secret
        :param signature_method: One of HMAC-SHA1, RSA-SHA1 and PLAINTEXT
        :param request_token: The oauth token used to authenticate users
        :param callback: The url an authorized user should be redirected to
        :param verifier: Used in combination with request_token to request 
                        an access_token
        :param access_token: The oauth token used to request resources
        :param token_secret: A secret often used in combination with access_token
        :param rsa_key: The string of a private RSA key
        """
        self.client_key = client_key      
        self.client_secret = client_secret
        self.request_token = request_token
        self.access_token = access_token
        self.token_secret = token_secret
        self.rsa_key = rsa_key
        self.callback = callback
        self.signature_method = signature_method
        self.verifier = verifier

    def _verify_fields(self):
        # OAuth requires a valid signature method
        if not self.signature_method in OAuth.SIG_METHODS:
            raise OAuthError("No signature method")

        # Only warn since client key is optional in theory
        if not self.client_key:
            warn("No client identifier (consumer key) provided, this is " +
                 "almost always required.")

        # Usually only client secret is needed in this step, the token
        # secret is usually used later with the access token
        if not self.client_secret and "HMAC-SHA1" == self.signature_method:
            warn("No client shared secret (consumer secret) provided.")

        # Request token and Access token are simply for convenience, 
        # they cannot be used at the same time
        if self.request_token and self.access_token:
            raise OAuthError("Use either access token or request, not both.")

        if not self.rsa_key and "RSA-SHA1" == self.signature_method:
            raise OAuthError("No RSA key provided")

    def _sign(self, url, params, method):
        # Crypto signature of all oauth parameters, no data used this time
        if "HMAC-SHA1" == self.signature_method:
            return sign_hmac(method, url, params, 
                               self.client_secret, self.token_secret)

        elif "RSA-SHA1" == self.signature_method:
            return sign_rsa(method, url, params, self.rsa_key)

        elif "PLAINTEXT" == self.signature_method:
            return sign_plain(self.client_secret, self.token_secret)

        else:
            raise OAuthError("Invalid signature method")
           
    def _prepare_params(self, data=list()):
        """Generate parameters from all set fields"""
        self._verify_fields()
        args = {}

        if self.client_key:
            args["client_key"] = self.client_key

        if self.access_token:
            args["access_token"] = self.access_token

        if self.request_token:
            args["request_token"] = self.request_token

        if self.callback:
            args["callback"] = self.callback

        if self.verifier:
            args["verifier"] = self.verifier

        params = generate_params(**args)
        params.extend(self._convert_to_list(data))
        return params
    
    def _convert_to_list(self, data):
       
        if isinstance(data, str):
            return [(escape(k), escape(v)) for k, v in parse_qsl(data)]

        elif isinstance(data, dict):
            return [(escape(k), escape(v)) for k, v in data.items()]

        elif isinstance(data, list):
            return [(escape(k), escape(v)) for k, v in data]

        else:
            raise OAuthError("Could not convert data of type %s" % type(data))

    def auth_header(self, url, data=list(), method="POST", realm=None):
        """Construct a signed OAuth 1.0 RFC Authorization header

        :param url: The requested server url.
        :param data: A dictionary(or tuple list) of (form-)data to send.
        :param method: The HTTP method. GET, POST, PUT, etc.
        :param realm: The scope/realm of the request.
        :return: A string to be used with the Authorization HTTP header.
        """
        params = self._prepare_params(data)
        params.append(("oauth_signature", self._sign(url, params, method)))
        return prepare_authorization_header(params, realm) 

    def verify_auth_header(self, url, header, data=list(), method="POST"):
        """Verify a signed OAuth 1.0 RFC Authorization header

        :param url: The full request url (with query components).
        :param data: A string, dictionary(or tuple list) of unescaped sent (form-)data.
        :param method: The HTTP method. GET, POST, PUT, etc.
        :param realm: The scope/realm of the request.
        :return: True or False.
        """
        # Header pattern: OAuth [{k}={v},] (without ending comma), i.e.
        # OAuth realm="photos", oauth_consumer_key="w3489sfkjhsdf"
        # OAuth oauth_consumer_key="w3489sfkjhsdf", oauth_token="34785sfikasdf"
        params = []
        realm = None
        client_sig = None

        # Remove "OAuth " and split in pairs  
        for pair in header[6:].split(","):
            k, _, v = pair.partition("=")

            # Remove whitespace and enclosing quotation marks
            k, v = k.strip(), v.strip()[1:-1]
            
            # Do not include signature nor realm
            if k == "oauth_signature":
                client_sig = v
            elif k == "realm":
                realm = v
            else:
                params.append((k, v))
    
        # For a correct signature, data must be appended to params
        params.extend(self._convert_to_list(data))
        if "RSA-SHA1" == self.signature_method:
            return verify_rsa(method, url, params, self.rsa_key, client_sig)
        else:
            return client_sig == self._sign(url, params, method)

    def uri_query(self, url, data=list(), method="POST"):
        """Construct a signed OAuth 1.0 RFC Request URI Query

        :param url: The request server url.
        :param data: A dictionary(or tuple list) of (form-)data to send.
        :param method: The HTTP method. GET, POST, PUT, etc.
        :return: The input URL modified to include the necessary OAuth parameters.
        """
        # We do not want to include the form data in the URI
        query = self._prepare_params()
        params = query[:]

        if isinstance(data, dict):
            data = data.items()

        for k, v in data:
            params.append((escape(k), escape(v)))

        query.append(("oauth_signature", self._sign(url, params, method)))
        return prepare_request_uri_query(query, url) 

    def verify_uri_query(self, url, data=list(), method="POST"):
        """Verify a signed OAuth 1.0 RFC Request URI Query

        :param url: The full request url (with query components).
        :param data: A string, dictionary(or tuple list) of unescaped sent (form-)data.
        :param method: The HTTP method. GET, POST, PUT, etc.
        :return: True or False.
        """
        # OAuth parameters passed as query components in the url
        # Need to extra parameters from the url
        # Then reconstruct the url without oauth parameters
        params = []
        qcs =  []
        client_sig = None

        sch, net, path, par, query, fra = urlparse(url)
        for k,v in parse_qsl(query, True):
            k, v = escape(k), escape(v)
            if k.startswith("oauth_"):
                if k == "oauth_signature":
                    client_sig = v
                else:
                    params.append((k, v))
            else:
                qcs.append((k, v))

        query = "&".join(["%s=%s" % (k, v) for k,v in qcs])
        old_url = urlunparse((sch, net, path, par, query, fra))
        params.extend(self._convert_to_list(data))
        if "RSA-SHA1" == self.signature_method:
            return verify_rsa(method, old_url, params, self.rsa_key, client_sig)
        else:
            return client_sig == self._sign(old_url, params, method)

    def form_body(self, url, data=list(), method="POST"):
        """Construct a signed OAuth 1.0 RFC Form Encoded Body

        :param url: The request server url.
        :param data: A dictionary(or tuple list) of (form-)data to send.
        :param method: The HTTP method. GET, POST, PUT, etc.
        :return: A string, including OAuth parameters, to be sent in the request body.
        """
        params = self._prepare_params(data)
        params.append(("oauth_signature", self._sign(url, params, method)))
        return prepare_form_encoded_body(params) 

    def verify_form_body(self, url, body, method="POST"):
        """Verify a signed OAuth 1.0 RFC Form Encoded Body

        :param url: The full request url (with query components).
        :param data: A string, dictionary(or tuple list) of sent unescaped (form-)data.
        :param method: The HTTP method. GET, POST, PUT, etc.
        :return: True or False.
        """
        # OAuth parameters passed in the body of the request
        params = self._convert_to_list(body)
        client_sig = dict(params)["oauth_signature"]
        if "RSA-SHA1" == self.signature_method:
            return verify_rsa(method, url, params, self.rsa_key, client_sig)
        else:
            return client_sig == self._sign(url, params, method)


