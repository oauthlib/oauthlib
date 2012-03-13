# -*- coding: utf-8 -*-
from __future__ import absolute_import

"""
oauthlib.oauth
~~~~~~~~~~~~~~

This module is a generic implementation of various logic needed
for signing OAuth requests.
"""

import urlparse

from . import parameters, signature, utils

SIGNATURE_HMAC = u"HMAC-SHA1"
SIGNATURE_RSA = u"RSA-SHA1"
SIGNATURE_PLAINTEXT = u"PLAINTEXT"

SIGNATURE_TYPE_AUTH_HEADER = u'AUTH_HEADER'
SIGNATURE_TYPE_QUERY = u'QUERY'

class OAuthClient(object):
    """An OAuth client used to sign OAuth requests"""
    def __init__(self, client_key, client_secret,
            resource_owner_key, resource_owner_secret, callback_uri=None,
            signature_method=SIGNATURE_HMAC,
            signature_type=SIGNATURE_TYPE_AUTH_HEADER,
            rsa_key=None, verifier=None):
        self.client_key = client_key
        self.client_secret = client_secret
        self.resource_owner_key = resource_owner_key
        self.resource_owner_secret = resource_owner_secret
        self.signature_method = signature_method
        self.signature_type = signature_type
        self.callback_uri = callback_uri
        self.rsa_key = rsa_key
        self.verifier = verifier

    def get_oauth_signature(self, uri, http_method=u'GET', body=None,
            authorization_header=None):
        """Get an OAuth signature to be used in signing a request"""
        if self.signature_method == SIGNATURE_PLAINTEXT:
            # fast-path
            return signature.sign_plaintext(self.client_secret,
                self.resource_owner_secret)

        query = urlparse.urlparse(uri).query
        params = signature.collect_parameters(uri_query=query,
            authorization_header=authorization_header, body=body)
        normalized_params = signature.normalize_parameters(params)
        normalized_uri = signature.normalize_base_string_uri(uri)
        base_string = signature.construct_base_string(http_method,
            normalized_uri, normalized_params)
        if self.signature_method == SIGNATURE_HMAC:
            return signature.sign_hmac_sha1(base_string, self.client_secret,
                self.resource_owner_secret)
        elif self.signature_method == SIGNATURE_RSA:
            return signature.sign_rsa_sha1(base_string, self.rsa_key)
        else:
            return signature.sign_plaintext(self.client_secret,
                self.resource_owner_secret)

    def get_oauth_params(self):
        """Get the basic OAuth parameters to be used in generating a signature.
        """
        params = [
            (u'oauth_nonce', utils.generate_nonce()),
            (u'oauth_timestamp', utils.generate_timestamp()),
            (u'oauth_version', u'1.0'),
            (u'oauth_signature_method', self.signature_method),
            (u'oauth_consumer_key', self.client_key),
            (u'oauth_token', self.resource_owner_key),
        ]
        if self.callback_uri:
            params.append((u'oauth_callback', self.callback_uri))
        if self.verifier:
            params.append((u'oauth_verifier', self.verifier))

        return params

    def _contribute_parameters(self, uri, params):
        if self.signature_type == SIGNATURE_TYPE_AUTH_HEADER:
            authorization_header = parameters.prepare_authorization_header(
                params)
            complete_uri = uri
        else:
            authorization_header = None
            complete_uri = parameters.prepare_request_uri_query(params, uri)

        return complete_uri, authorization_header

    def sign_request(self, uri, http_method=u'GET', body=None):
        """Get the signed uri and authorization header.
        Authorization header will be None if signature type is "query".
        """
        # get the OAuth params and contribute them to either the uri or
        # authorization header
        params = self.get_oauth_params()
        complete_uri, authorization_header = self._contribute_parameters(uri,
            params)

        # use the new uri and authorization header to generate a signature and
        # contribute that signature to the OAuth parameters
        oauth_signature = self.get_oauth_signature(complete_uri,
            http_method=http_method, body=body,
            authorization_header=authorization_header)
        params.append((u'oauth_signature', oauth_signature))

        # take the new OAuth params with signature and contribute the
        # now-complete parameters to the uri or authorization header
        return self._contribute_parameters(uri, params)

class OAuthServer(object):
    def __init__(self, signature_method=SIGNATURE_HMAC, rsa_key=None):
        self.signature_method = signature_method
        self.rsa_key = rsa_key

    def get_client_secret(self, client_key):
        raise NotImplementedError("Subclasses must implement this function.")

    def get_resource_owner_secret(self, resource_owner_key):
        raise NotImplementedError("Subclasses must implement this function.")

    def check_timestamp_and_nonce(self, timestamp, nonce):
        raise NotImplementedError("Subclasses must implement this function.")

    def check_request_signature(self, uri, http_method=u'GET', body=None,
            authorization_header=None):
        """Check a request's supplied signature to make sure the request is
        valid.

        Per `section 3.2`_ of the spec.

        .. _`section 3.2`: http://tools.ietf.org/html/rfc5849#section-3.2
        """
        # extract parameters
        uri_query = urlparse.urlparse(uri).query
        params = dict(signature.collect_parameters(uri_query=uri_query,
            authorization_header=authorization_header, body=body,
            exclude_oauth_signature=False))

        # ensure required parameters exist
        request_signature = params.get(u'oauth_signature')
        client_key = params.get(u'oauth_consumer_key')
        resource_owner_key = params.get(u'oauth_token')
        nonce = params.get(u'oauth_nonce')
        timestamp = params.get(u'oauth_timestamp')
        callback_uri = params.get(u'oauth_callback')
        verifier = params.get(u'oauth_verifier')
        if not all((signature, client_key, resource_owner_key, nonce,
                timestamp)):
            return False

        # if version is supplied, it must be "1.0"
        if u'oauth_version' in params and params[u'oauth_version'] != u'1.0':
            return False

        # ensure the nonce and timestamp haven't been used before
        if not self.check_timestamp_and_nonce(timestamp, nonce):
            return False

        client_secret = self.get_client_secret(client_key)
        resource_owner_secret = self.get_resource_owner_secret(
            resource_owner_key)
        if authorization_header:
            signature_type = SIGNATURE_TYPE_AUTH_HEADER
        else:
            signature_type = SIGNATURE_TYPE_QUERY

        oauth_client = OAuthClient(client_key, client_secret,
            resource_owner_key, resource_owner_secret,
            callback_uri=callback_uri,
            signature_method=self.signature_method,
            signature_type=signature_type,
            rsa_key=self.rsa_key, verifier=verifier)
        client_signature = oauth_client.get_oauth_signature(uri,
            body=body, authorization_header=authorization_header)
        return client_signature == request_signature

