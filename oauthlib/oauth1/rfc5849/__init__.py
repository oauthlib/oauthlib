# -*- coding: utf-8 -*-
from __future__ import absolute_import

"""
oauthlib.oauth1.rfc5849
~~~~~~~~~~~~~~

This module is an implementation of various logic needed
for signing and checking OAuth 1.0 RFC 5849 requests.
"""

import urlparse

from . import parameters, signature, utils

SIGNATURE_HMAC = u"HMAC-SHA1"
SIGNATURE_RSA = u"RSA-SHA1"
SIGNATURE_PLAINTEXT = u"PLAINTEXT"
SIGNATURE_METHODS = (SIGNATURE_HMAC, SIGNATURE_RSA, SIGNATURE_PLAINTEXT)

SIGNATURE_TYPE_AUTH_HEADER = u'AUTH_HEADER'
SIGNATURE_TYPE_QUERY = u'QUERY'
SIGNATURE_TYPE_BODY = u'BODY'


class Client(object):
    """A client used to sign OAuth 1.0 RFC 5849 requests"""
    def __init__(self, client_key,
            client_secret=None,
            resource_owner_key=None,
            resource_owner_secret=None,
            callback_uri=None,
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

        if self.signature_method == SIGNATURE_RSA and self.rsa_key is None:
            raise ValueError('rsa_key is required when using RSA signature method.')

    def get_oauth_signature(self, uri, http_method=u'GET', body='',
            headers=None):
        """Get an OAuth signature to be used in signing a request"""
        headers = headers or {}

        if self.signature_method == SIGNATURE_PLAINTEXT:
            # fast-path
            return signature.sign_plaintext(self.client_secret,
                self.resource_owner_secret)

        headers = headers or {}
        query = urlparse.urlparse(uri).query
        params = signature.collect_parameters(uri_query=query,
            body=body, headers=headers)
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
        ]
        if self.resource_owner_key:
            params.append((u'oauth_token', self.resource_owner_key))
        if self.callback_uri:
            params.append((u'oauth_callback', self.callback_uri))
        if self.verifier:
            params.append((u'oauth_verifier', self.verifier))

        return params

    def _contribute_parameters(self, uri, params, body='', headers=None):
        if self.signature_type not in (SIGNATURE_TYPE_BODY,
                                       SIGNATURE_TYPE_QUERY,
                                       SIGNATURE_TYPE_AUTH_HEADER):
            raise ValueError('Unknown signature type used.')

        # defaults
        headers = headers or {}
        complete_uri = uri

        # Sign with the specified signature type
        if self.signature_type == SIGNATURE_TYPE_AUTH_HEADER:
            headers = parameters.prepare_headers(
                params, headers)

        if self.signature_type == SIGNATURE_TYPE_BODY:
            body = parameters.prepare_form_encoded_body(params, body)

        if self.signature_type == SIGNATURE_TYPE_QUERY:
            complete_uri = parameters.prepare_request_uri_query(params, uri)

        return complete_uri, body, headers

    def sign_request(self, uri, http_method=u'GET', body='', headers=None):
        """Get the signed uri and authorization header.
        Authorization header will be None if signature type is "query".
        """
        headers = headers or {}

        # get the OAuth params and contribute them to either the uri or
        # authorization header
        params = self.get_oauth_params()
        complete_uri, body, headers = self._contribute_parameters(uri,
            params, body=body, headers=headers)

        # use the new uri and authorization header to generate a signature and
        # contribute that signature to the OAuth parameters
        oauth_signature = self.get_oauth_signature(complete_uri,
            http_method=http_method, body=body,
            headers=headers)
        params.append((u'oauth_signature', oauth_signature))

        # take the new OAuth params with signature and contribute the
        # now-complete parameters to the uri or authorization header
        return self._contribute_parameters(uri, params)


class Server(object):
    """A server used to verify OAuth 1.0 RFC 5849 requests"""
    def __init__(self, signature_method=SIGNATURE_HMAC, rsa_key=None):
        self.signature_method = signature_method
        self.rsa_key = rsa_key

    def get_client_secret(self, client_key):
        raise NotImplementedError("Subclasses must implement this function.")

    def get_resource_owner_secret(self, resource_owner_key):
        raise NotImplementedError("Subclasses must implement this function.")

    def get_signature_type_and_params(self, uri_query, headers, body):
        signature_types_with_oauth_params = filter(lambda s: s[1], (
            (SIGNATURE_TYPE_AUTH_HEADER, utils.filter_oauth_params(
                signature.collect_parameters(header=header,
                exclude_oauth_signature=False))),
            (SIGNATURE_TYPE_BODY, utils.filter_oauth_params(
                signature.collect_parameters(body=body,
                exclude_oauth_signature=False))),
            (SIGNATURE_TYPE_QUERY, utils.filter_oauth_params(
                signature.collect_parameters(uri_query=uri_query,
                exclude_oauth_signature=False))),
        ))

        if len(signature_types_with_params) > 1:
            raise ValueError('oauth_ params must come from only 1 signature type but were found in %s' % ', '.join(
                [s[0] for s in signature_types_with_params]))
        try:
            signature_type, params = signature_types_with_params[0]
        except IndexError:
            raise ValueError('oauth_ params are missing. Could not determine signature type.')

        return signature_type, dict(params)

    def check_client_key(self, client_key):
        raise NotImplementedError("Subclasses must implement this function.")

    def check_resource_owner_key(self, client_key, resource_owner_key):
        raise NotImplementedError("Subclasses must implement this function.")

    def check_timestamp_and_nonce(self, timestamp, nonce):
        raise NotImplementedError("Subclasses must implement this function.")

    def check_request_signature(self, uri, http_method=u'GET', body='',
            headers=None):
        """Check a request's supplied signature to make sure the request is
        valid.

        Servers should return HTTP status 400 if a ValueError exception
        is raised and HTTP status 401 on return value False.

        Per `section 3.2`_ of the spec.

        .. _`section 3.2`: http://tools.ietf.org/html/rfc5849#section-3.2
        """
        headers = headers or {}
        signature_type = None
        uri_query = urlparse.urlparse(uri).query

        signature_type, params = self.get_signature_type_and_params(uri_query,
            headers, body)

        # the parameters may not include duplicate oauth entries
        filtered_params = utils.filter_oauth_params(params)
        if len(filtered_params) != len(params):
            raise ValueError("Duplicate OAuth entries.")

        params = dict(params)
        request_signature = params.get(u'oauth_signature')
        client_key = params.get(u'oauth_consumer_key')
        resource_owner_key = params.get(u'oauth_token')
        nonce = params.get(u'oauth_nonce')
        timestamp = params.get(u'oauth_timestamp')
        callback_uri = params.get(u'oauth_callback')
        verifier = params.get(u'oauth_verifier')
        signature_method = params.get(u'oauth_signature')

        # ensure all mandatory parameters are present
        if not all((request_signature, client_key, nonce,
                    timestamp, signature_method)):
            raise ValueError("Missing OAuth parameters.")

        # if version is supplied, it must be "1.0"
        if u'oauth_version' in params and params[u'oauth_version'] != u'1.0':
            raise ValueError("Invalid OAuth version.")

        # signature method must be valid
        if not signature_method in SIGNATURE_METHODS:
            raise ValueError("Invalid signature method.")

        # ensure client key is valid
        if not self.check_client_key(client_key):
            return False

        # ensure resource owner key is valid and not expired
        if not self.check_resource_owner_key(client_key, resource_owner_key):
            return False

        # ensure the nonce and timestamp haven't been used before
        if not self.check_timestamp_and_nonce(timestamp, nonce):
            return False

        # FIXME: extract realm, then self.check_realm

        # oauth_client parameters depend on client chosen signature method
        # which may vary for each request, section 3.4
        # HMAC-SHA1 and PLAINTEXT share parameters
        if signature_method == RSA_SHA1:
            oauth_client = Client(client_key,
                resource_owner_key=resource_owner_key,
                callback_uri=callback_uri,
                signature_method=signature_method,
                signature_type=signature_type,
                rsa_key=self.rsa_key, verifier=verifier)
        else:
            client_secret = self.get_client_secret(client_key)
            resource_owner_secret = self.get_resource_owner_secret(
                resource_owner_key)
            oauth_client = Client(client_key,
                client_secret=client_secret,
                resource_owner_key=resource_owner_key,
                resource_owner_secret=resource_owner_secret,
                callback_uri=callback_uri,
                signature_method=signature_method,
                signature_type=signature_type,
                verifier=verifier)

        client_signature = oauth_client.get_oauth_signature(uri,
            body=body, headers=headers)

        # FIXME: use near constant time string compare to avoid timing attacks
        return client_signature == request_signature

