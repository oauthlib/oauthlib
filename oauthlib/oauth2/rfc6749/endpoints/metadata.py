# -*- coding: utf-8 -*-
"""
oauthlib.oauth2.rfc6749.endpoint.metadata
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An implementation of the `OAuth 2.0 Authorization Server Metadata`.

.. _`OAuth 2.0 Authorization Server Metadata`: https://tools.ietf.org/html/rfc8414
"""
from __future__ import absolute_import, unicode_literals

import copy
import json
import logging

from ....common import unicode_type
from .base import BaseEndpoint, catch_errors_and_unavailability
from .authorization import AuthorizationEndpoint
from .introspect import IntrospectEndpoint
from .token import TokenEndpoint
from .revocation import RevocationEndpoint


log = logging.getLogger(__name__)


class MetadataEndpoint(BaseEndpoint):

    """OAuth2.0 Authorization Server Metadata endpoint.

   This specification generalizes the metadata format defined by
   `OpenID Connect Discovery 1.0` in a way that is compatible
   with OpenID Connect Discovery while being applicable to a wider set
   of OAuth 2.0 use cases.  This is intentionally parallel to the way
   that `OAuth 2.0 Dynamic Client Registration Protocol` [RFC7591]
   generalized the dynamic client registration mechanisms defined by
   `OpenID Connect Dynamic Client Registration 1.0`
   in a way that is compatible with it.

   .. _`OpenID Connect Discovery 1.0`: http://openid.net/specs/openid-connect-discovery-1_0.html
   .. _`OAuth 2.0 Dynamic Client Registration Protocol`: https://tools.ietf.org/html/rfc7591
   .. _`OpenID Connect Dynamic Client Registration 1.0`: https://openid.net/specs/openid-connect-registration-1_0.html
   """

    def __init__(self, endpoints, claims={}, raise_errors=True):
        assert isinstance(claims, dict)
        for endpoint in endpoints:
            assert isinstance(endpoint, BaseEndpoint)

        BaseEndpoint.__init__(self)
        self.raise_errors = raise_errors
        self.endpoints = endpoints
        self.initial_claims = claims
        self.claims = self.validate_metadata_server()

    @catch_errors_and_unavailability
    def create_metadata_response(self, uri, http_method='GET', body=None,
                                 headers=None):
        """Create metadata response
        """
        headers = {
            'Content-Type': 'application/json'
        }
        return headers, json.dumps(self.claims), 200

    def validate_metadata(self, array, key, is_required=False, is_list=False, is_url=False, is_issuer=False):
        if not self.raise_errors:
            return

        if key not in array:
            if is_required:
                raise ValueError("key {} is a mandatory metadata.".format(key))

        elif is_issuer:
            if not array[key].startswith("https"):
                raise ValueError("key {}: {} must be an HTTPS URL".format(key, array[key]))
            if "?" in array[key] or "&" in array[key] or "#" in array[key]:
                raise ValueError("key {}: {} must not contain query or fragment components".format(key, array[key]))

        elif is_url:
            if not array[key].startswith("http"):
                raise ValueError("key {}: {} must be an URL".format(key, array[key]))

        elif is_list:
            if not isinstance(array[key], list):
                raise ValueError("key {}: {} must be an Array".format(key, array[key]))
            for elem in array[key]:
                if not isinstance(elem, unicode_type):
                    raise ValueError("array {}: {} must contains only string (not {})".format(key, array[key], elem))

    def validate_metadata_token(self, claims, endpoint):
        claims.setdefault("grant_types_supported", list(endpoint._grant_types.keys()))
        claims.setdefault("token_endpoint_auth_methods_supported", ["client_secret_post", "client_secret_basic"])

        self.validate_metadata(claims, "grant_types_supported", is_list=True)
        self.validate_metadata(claims, "token_endpoint_auth_methods_supported", is_list=True)
        self.validate_metadata(claims, "token_endpoint_auth_signing_alg_values_supported", is_list=True)
        self.validate_metadata(claims, "token_endpoint", is_required=True, is_url=True)

    def validate_metadata_authorization(self, claims, endpoint):
        claims.setdefault("response_types_supported", list(self._response_types.keys()))
        claims.setdefault("response_modes_supported", ["query", "fragment"])

        self.validate_metadata(claims, "response_types_supported", is_required=True, is_list=True)
        self.validate_metadata(claims, "response_modes_supported", is_list=True)
        if "code" in claims["response_types_supported"]:
            self.validate_metadata(claims, "code_challenge_methods_supported", is_list=True)
        self.validate_metadata(claims, "authorization_endpoint", is_required=True, is_url=True)

    def validate_metadata_revocation(self, claims, endpoint):
        claims.setdefault("revocation_endpoint_auth_methods_supported",
                          ["client_secret_post", "client_secret_basic"])

        self.validate_metadata(claims, "revocation_endpoint_auth_methods_supported", is_list=True)
        self.validate_metadata(claims, "revocation_endpoint_auth_signing_alg_values_supported", is_list=True)
        self.validate_metadata(claims, "revocation_endpoint", is_required=True, is_url=True)

    def validate_metadata_introspection(self, claims, endpoint):
        claims.setdefault("introspection_endpoint_auth_methods_supported",
                          ["client_secret_post", "client_secret_basic"])

        self.validate_metadata(claims, "introspection_endpoint_auth_methods_supported", is_list=True)
        self.validate_metadata(claims, "introspection_endpoint_auth_signing_alg_values_supported", is_list=True)
        self.validate_metadata(claims, "introspection_endpoint", is_required=True, is_url=True)

    def validate_metadata_server(self):
        """
        Authorization servers can have metadata describing their
        configuration.  The following authorization server metadata values
        are used by this specification. More details can be found in `RFC8414` :

       issuer
          REQUIRED

       authorization_endpoint
          URL of the authorization server's authorization endpoint
          [RFC6749].  This is REQUIRED unless no grant types are supported
          that use the authorization endpoint.

       token_endpoint
          URL of the authorization server's token endpoint [RFC6749].  This
          is REQUIRED unless only the implicit grant type is supported.

       scopes_supported
          RECOMMENDED.

       response_types_supported
          REQUIRED.

       * Other OPTIONAL fields:
       jwks_uri
       registration_endpoint
       response_modes_supported
       grant_types_supported
       token_endpoint_auth_methods_supported
       token_endpoint_auth_signing_alg_values_supported
       service_documentation
       ui_locales_supported
       op_policy_uri
       op_tos_uri
       revocation_endpoint
       revocation_endpoint_auth_methods_supported
       revocation_endpoint_auth_signing_alg_values_supported
       introspection_endpoint
       introspection_endpoint_auth_methods_supported
       introspection_endpoint_auth_signing_alg_values_supported
       code_challenge_methods_supported

       Additional authorization server metadata parameters MAY also be used.
       Some are defined by other specifications, such as OpenID Connect
       Discovery 1.0 [OpenID.Discovery].

        .. _`RFC8414 section 2`: https://tools.ietf.org/html/rfc8414#section-2
        """
        claims = copy.deepcopy(self.initial_claims)
        self.validate_metadata(claims, "issuer", is_required=True, is_issuer=True)
        self.validate_metadata(claims, "jwks_uri", is_url=True)
        self.validate_metadata(claims, "scopes_supported", is_list=True)
        self.validate_metadata(claims, "service_documentation", is_url=True)
        self.validate_metadata(claims, "ui_locales_supported", is_list=True)
        self.validate_metadata(claims, "op_policy_uri", is_url=True)
        self.validate_metadata(claims, "op_tos_uri", is_url=True)

        for endpoint in self.endpoints:
            if isinstance(endpoint, TokenEndpoint):
                self.validate_metadata_token(claims, endpoint)
            if isinstance(endpoint, AuthorizationEndpoint):
                self.validate_metadata_authorization(claims, endpoint)
            if isinstance(endpoint, RevocationEndpoint):
                self.validate_metadata_revocation(claims, endpoint)
            if isinstance(endpoint, IntrospectEndpoint):
                self.validate_metadata_introspection(claims, endpoint)
        return claims
