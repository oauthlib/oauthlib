# -*- coding: utf-8 -*-
"""
oauthlib.oauth2.rfc7591.endpoint
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An implementation of the `OAuth2.0 Dynamic Client Registration Protocol`.

.. _`OAuth2.0 Dynamic Client Registration Protocol`: https://tools.ietf.org/html/rfc7591
"""
import logging

from ..rfc6749.endpoints.base import BaseEndpoint, catch_errors_and_unavailability


log = logging.getLogger(__name__)


class DynamicClientRegistrationEndpoint(BaseEndpoint):

    """OAuth2.0 Dynamic Client Registration endpoint.

   This specification defines mechanisms for dynamically registering
   OAuth 2.0 clients with authorization servers.  Registration requests
   send a set of desired client metadata values to the authorization
   server.  The resulting registration responses return a client
   identifier to use at the authorization server and the client metadata
   values registered for the client.  The client can then use this
   registration information to communicate with the authorization server
   using the OAuth 2.0 protocol.  This specification also defines a set
   of common client metadata fields and values for clients to use during
   registration.

   The client registration endpoint is an OAuth 2.0 endpoint defined in
   this document that is designed to allow a client to be registered
   with the authorization server.  The client registration endpoint MUST
   accept HTTP POST messages with request parameters encoded in the
   entity body using the "application/json" format.  The client
   registration endpoint MUST be protected by a transport-layer security
   mechanism, as described in Section 5.

   The client registration endpoint MAY be an OAuth 2.0 [RFC6749]
   protected resource and it MAY accept an initial access token in the
   form of an OAuth 2.0 access token to limit registration to only
   previously authorized parties.  The method by which the initial
   access token is obtained by the client or developer is generally out
   of band and is out of scope for this specification.  The method by
   which the initial access token is verified and validated by the
   client registration endpoint is out of scope for this specification.

   To support open registration and facilitate wider interoperability,
   the client registration endpoint SHOULD allow registration requests
   with no authorization (which is to say, with no initial access token
   in the request).  These requests MAY be rate-limited or otherwise
   limited to prevent a denial-of-service attack on the client
   registration endpoint.
   """

    @catch_errors_and_unavailability
    def create_registration_response(self):
        """Create registration valid or invalid response.

        This operation registers a client with the authorization
        server. The authorization server assigns this client a unique
        client identifier, optionally assigns a client secret, and
        associates the metadata provided in the request with the
        issued client identifier. The request includes any client
        metadata parameters being specified for the client during the
        registration.  The authorization server MAY provision default
        values for any items omitted in the client metadata.

        To register, the client or developer sends an HTTP POST to the
        client registration endpoint with a content type of
        "application/json".  The HTTP Entity Payload is a JSON
        [RFC7159] document consisting of a JSON object and all
        requested client metadata values as top-level members of that
        JSON object.

        OAuthlib Framework parse the HTTP request, check and validate
        the metadata. They are then processed thru the implementation
        via the RequestValidator.

        Note that if you want to protect the registration endpoint
        with a Bearer Token, you can use this Endpoint in combination
        with :py:class:`oauthlib.oauth2.ResourceEndpoint`.

        The implementation has to handle the following functions:

        * approve software statement, if needed,
        * store the metadata associated with the generated client_id

        The relevant RequestValidator methods to implement are:

        * validate_software_statement
        * register_client_metadata

        See OAuth2.0 Dynamic Client Registration protocol [`RFC7591`_].

        .. _`RFC7591`: https://tools.ietf.org/html/rfc7591
        """

    def validate_registration_request(self):
        """
        Check if the Dynamic Client Registration request is valid.

        Client metadata values can be either communicated directly in
        the body of a registration request, or included as claims in a
        software statement; a mixture of both is also possible.
        If the same client metadata name is present in both locations
        and the software statement is trusted by the authorization
        server, the value of a claim in the software statement MUST
        take precedence.  The following checks are applied:

        redirect_uris
            Array of redirection URI strings.

        client_uri
        logo_uri
        tos_uri
        policy_uri
        jwks_uri
          Checks that's a valid URL string

        contacts
          Array of strings

        jwks
         The value of this field MUST be a JSON object containing a
         valid JWK Set.

        The "jwks_uri" and "jwks" parameters MUST NOT both be present
        in the same request or response.

        grant_types
        response_types
            The "grant_types" and "response_types" values described
            above are partially orthogonal, as they refer to arguments
            passed to different endpoints in the OAuth protocol.
            However, they are related in that the "grant_types"
            available to a client influence the "response_types" that
            the client is allowed to use, and vice versa.  For
            instance, a "grant_types" value that includes
            "authorization_code" implies a "response_types" value that
            includes "code", as both values are defined as part of the
            OAuth 2.0 authorization code grant. As such, a server
            supporting these fields SHOULD take steps to ensure that a
            client cannot register itself into an inconsistent state,
            for example, by returning an "invalid_client_metadata"
            error response to an inconsistent registration request.

            The correlation between the two fields is listed in the
            table below.

   +-----------------------------------------------+-------------------+
   | grant_types value includes:                   | response_types    |
   |                                               | value includes:   |
   +-----------------------------------------------+-------------------+
   | authorization_code                            | code              |
   | implicit                                      | token             |
   | password                                      | (none)            |
   | client_credentials                            | (none)            |
   | refresh_token                                 | (none)            |
   | urn:ietf:params:oauth:grant-type:jwt-bearer   | (none)            |
   | urn:ietf:params:oauth:grant-type:saml2-bearer | (none)            |
   +-----------------------------------------------+-------------------+

        See OAuth2.0 Dynamic Client Registration protocol [`RFC7591`_].

        .. _`RFC7591`: https://tools.ietf.org/html/rfc7591
        """
