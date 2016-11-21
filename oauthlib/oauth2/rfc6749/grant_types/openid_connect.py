# -*- coding: utf-8 -*-
"""
oauthlib.oauth2.rfc6749.grant_types.openid_connect
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""
from __future__ import unicode_literals, absolute_import

from json import loads
import logging

import datetime

from .base import GrantTypeBase
from .authorization_code import AuthorizationCodeGrant
from .implicit import ImplicitGrant
from ..errors import InvalidRequestError, LoginRequired, ConsentRequired
from ..request_validator import RequestValidator

log = logging.getLogger(__name__)

class OIDCNoPrompt(Exception):
    """Exception used to inform users that no explicit authorization is needed.

    Normally users authorize requests after validation of the request is done.
    Then post-authorization validation is again made and a response containing
    an auth code or token is created. However, when OIDC clients request
    no prompting of user authorization the final response is created directly.

    Example (without the shortcut for no prompt)

    scopes, req_info = endpoint.validate_authorization_request(url, ...)
    authorization_view = create_fancy_auth_form(scopes, req_info)
    return authorization_view

    Example (with the no prompt shortcut)
    try:
        scopes, req_info = endpoint.validate_authorization_request(url, ...)
        authorization_view = create_fancy_auth_form(scopes, req_info)
        return authorization_view
    except OIDCNoPrompt:
        # Note: Location will be set for you
        headers, body, status = endpoint.create_authorization_response(url, ...)
        redirect_view = create_redirect(headers, body, status)
        return redirect_view
    """

    def __init__(self):
        msg = ("OIDC request for no user interaction received. Do not ask user "
               "for authorization, it should been done using silent "
               "authentication through create_authorization_response. "
               "See OIDCNoPrompt.__doc__ for more details.")
        super(OIDCNoPrompt, self).__init__(msg)


class AuthCodeGrantDispatcher(object):
    """
    This is an adapter class that will route simple Authorization Code requests, those that have response_type=code and a scope
    including 'openid' to either the default_auth_grant or the oidc_auth_grant based on the scopes requested.
    """
    def __init__(self, default_auth_grant=None, oidc_auth_grant=None):
        self.default_auth_grant = default_auth_grant
        self.oidc_auth_grant = oidc_auth_grant

    def _handler_for_request(self, request):
        handler = self.default_auth_grant

        if request.scopes and "openid" in request.scopes:
            handler = self.oidc_auth_grant

        log.debug('Selecting handler for request %r.', handler)
        return handler

    def create_authorization_response(self, request, token_handler):
        return self._handler_for_request(request).create_authorization_response(request, token_handler)

    def validate_authorization_request(self, request):
        return self._handler_for_request(request).validate_authorization_request(request)


class OpenIDConnectBase(GrantTypeBase):

    def __init__(self, request_validator=None):
        self.request_validator = request_validator or RequestValidator()

    def _inflate_claims(self, request):
        # this may be called multiple times in a single request so make sure we only de-serialize the claims once
        if request.claims and not isinstance(request.claims, dict):
            # specific claims are requested during the Authorization Request and may be requested for inclusion
            # in either the id_token or the UserInfo endpoint response
            # see http://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter
            try:
                request.claims = loads(request.claims)
            except Exception as ex:
                raise InvalidRequestError(description="Malformed claims parameter",
                                          uri="http://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter")

    def add_id_token(self, token, token_handler, request):
        # Treat it as normal OAuth 2 auth code request if openid is not present
        if not request.scopes or 'openid' not in request.scopes:
            return token

        # Only add an id token on auth/token step if asked for.
        if request.response_type and 'id_token' not in request.response_type:
            return token

        if 'state' not in token:
            token['state'] = request.state

        if request.max_age:
            d = datetime.datetime.utcnow()
            token['auth_time'] = d.isoformat("T") + "Z"

        # TODO: acr claims (probably better handled by server code using oauthlib in get_id_token)

        token['id_token'] = self.request_validator.get_id_token(token, token_handler, request)

        return token

    def openid_authorization_validator(self, request):
        """Perform OpenID Connect specific authorization request validation.

        display
                OPTIONAL. ASCII string value that specifies how the
                Authorization Server displays the authentication and consent
                user interface pages to the End-User. The defined values are:

                    page - The Authorization Server SHOULD display the
                    authentication and consent UI consistent with a full User
                    Agent page view. If the display parameter is not specified,
                    this is the default display mode.

                    popup - The Authorization Server SHOULD display the
                    authentication and consent UI consistent with a popup User
                    Agent window. The popup User Agent window should be of an
                    appropriate size for a login-focused dialog and should not
                    obscure the entire window that it is popping up over.

                    touch - The Authorization Server SHOULD display the
                    authentication and consent UI consistent with a device that
                    leverages a touch interface.

                    wap - The Authorization Server SHOULD display the
                    authentication and consent UI consistent with a "feature
                    phone" type display.

                The Authorization Server MAY also attempt to detect the
                capabilities of the User Agent and present an appropriate
                display.

        prompt
                OPTIONAL. Space delimited, case sensitive list of ASCII string
                values that specifies whether the Authorization Server prompts
                the End-User for reauthentication and consent. The defined
                values are:

                    none - The Authorization Server MUST NOT display any
                    authentication or consent user interface pages. An error is
                    returned if an End-User is not already authenticated or the
                    Client does not have pre-configured consent for the
                    requested Claims or does not fulfill other conditions for
                    processing the request. The error code will typically be
                    login_required, interaction_required, or another code
                    defined in Section 3.1.2.6. This can be used as a method to
                    check for existing authentication and/or consent.

                    login - The Authorization Server SHOULD prompt the End-User
                    for reauthentication. If it cannot reauthenticate the
                    End-User, it MUST return an error, typically
                    login_required.

                    consent - The Authorization Server SHOULD prompt the
                    End-User for consent before returning information to the
                    Client. If it cannot obtain consent, it MUST return an
                    error, typically consent_required.

                    select_account - The Authorization Server SHOULD prompt the
                    End-User to select a user account. This enables an End-User
                    who has multiple accounts at the Authorization Server to
                    select amongst the multiple accounts that they might have
                    current sessions for. If it cannot obtain an account
                    selection choice made by the End-User, it MUST return an
                    error, typically account_selection_required.

                The prompt parameter can be used by the Client to make sure
                that the End-User is still present for the current session or
                to bring attention to the request. If this parameter contains
                none with any other value, an error is returned.

        max_age
                OPTIONAL. Maximum Authentication Age. Specifies the allowable
                elapsed time in seconds since the last time the End-User was
                actively authenticated by the OP. If the elapsed time is
                greater than this value, the OP MUST attempt to actively
                re-authenticate the End-User. (The max_age request parameter
                corresponds to the OpenID 2.0 PAPE [OpenID.PAPE] max_auth_age
                request parameter.) When max_age is used, the ID Token returned
                MUST include an auth_time Claim Value.

        ui_locales
                OPTIONAL. End-User's preferred languages and scripts for the
                user interface, represented as a space-separated list of BCP47
                [RFC5646] language tag values, ordered by preference. For
                instance, the value "fr-CA fr en" represents a preference for
                French as spoken in Canada, then French (without a region
                designation), followed by English (without a region
                designation). An error SHOULD NOT result if some or all of the
                requested locales are not supported by the OpenID Provider.

        id_token_hint
                OPTIONAL. ID Token previously issued by the Authorization
                Server being passed as a hint about the End-User's current or
                past authenticated session with the Client. If the End-User
                identified by the ID Token is logged in or is logged in by the
                request, then the Authorization Server returns a positive
                response; otherwise, it SHOULD return an error, such as
                login_required. When possible, an id_token_hint SHOULD be
                present when prompt=none is used and an invalid_request error
                MAY be returned if it is not; however, the server SHOULD
                respond successfully when possible, even if it is not present.
                The Authorization Server need not be listed as an audience of
                the ID Token when it is used as an id_token_hint value. If the
                ID Token received by the RP from the OP is encrypted, to use it
                as an id_token_hint, the Client MUST decrypt the signed ID
                Token contained within the encrypted ID Token. The Client MAY
                re-encrypt the signed ID token to the Authentication Server
                using a key that enables the server to decrypt the ID Token,
                and use the re-encrypted ID token as the id_token_hint value.

        login_hint
                OPTIONAL. Hint to the Authorization Server about the login
                identifier the End-User might use to log in (if necessary).
                This hint can be used by an RP if it first asks the End-User
                for their e-mail address (or other identifier) and then wants
                to pass that value as a hint to the discovered authorization
                service. It is RECOMMENDED that the hint value match the value
                used for discovery. This value MAY also be a phone number in
                the format specified for the phone_number Claim. The use of
                this parameter is left to the OP's discretion.

        acr_values
                OPTIONAL. Requested Authentication Context Class Reference
                values. Space-separated string that specifies the acr values
                that the Authorization Server is being requested to use for
                processing this Authentication Request, with the values
                appearing in order of preference. The Authentication Context
                Class satisfied by the authentication performed is returned as
                the acr Claim Value, as specified in Section 2. The acr Claim
                is requested as a Voluntary Claim by this parameter.
        """

        # Treat it as normal OAuth 2 auth code request if openid is not present
        if not request.scopes or 'openid' not in request.scopes:
            return {}

        # prompt other than 'none' should be handled by the server code that uses oauthlib
        if request.prompt == 'none' and not request.id_token_hint:
            msg = "Prompt is set to none yet id_token_hint is missing."
            raise InvalidRequestError(request=request, description=msg)

        if request.prompt == 'none':
            if not self.request_validator.validate_silent_login(request):
                raise LoginRequired(request=request)
            if not self.request_validator.validate_silent_authorization(request):
                raise ConsentRequired(request=request)

        self._inflate_claims(request)

        if not self.request_validator.validate_user_match(
            request.id_token_hint, request.scopes, request.claims, request):
            msg = "Session user does not match client supplied user."
            raise LoginRequired(request=request, description=msg)


        request_info = {
            'display': request.display,
            'prompt': request.prompt.split() if request.prompt else [],
            'ui_locales': request.ui_locales.split() if request.ui_locales else [],
            'id_token_hint': request.id_token_hint,
            'login_hint': request.login_hint,
            'claims': request.claims
        }

        return request_info

    def openid_implicit_authorization_validator(self, request):
        """Additional validation when following the implicit flow.
        """
        # Undefined in OpenID Connect, fall back to OAuth2 definition.
        if request.response_type == 'token':
            return {}

        # Treat it as normal OAuth 2 auth code request if openid is not present
        if not request.scopes or 'openid' not in request.scopes:
            return {}

        # REQUIRED. String value used to associate a Client session with an ID
        # Token, and to mitigate replay attacks. The value is passed through
        # unmodified from the Authentication Request to the ID Token.
        # Sufficient entropy MUST be present in the nonce values used to
        # prevent attackers from guessing values. For implementation notes, see
        # Section 15.5.2.
        if not request.nonce:
            desc = 'Request is missing mandatory nonce parameter.'
            raise InvalidRequestError(request=request, description=desc)

        self._inflate_claims(request)

        return {'nonce': request.nonce, 'claims': request.claims}

class OpenIDConnectAuthCode(OpenIDConnectBase):

    def __init__(self, request_validator=None):
        self.request_validator = request_validator or RequestValidator()
        super(OpenIDConnectAuthCode, self).__init__(
            request_validator=self.request_validator)
        self.auth_code = AuthorizationCodeGrant(
            request_validator=self.request_validator)
        self.auth_code.register_authorization_validator(
            self.openid_authorization_validator)
        self.auth_code.register_token_modifier(self.add_id_token)

    @property
    def refresh_token(self):
        return self.auth_code.refresh_token

    @refresh_token.setter
    def refresh_token(self, value):
        self.auth_code.refresh_token = value

    def create_authorization_code(self, request):
        return self.auth_code.create_authorization_code(request)

    def create_authorization_response(self, request, token_handler):
        return self.auth_code.create_authorization_response(
            request, token_handler)

    def create_token_response(self, request, token_handler):
        return self.auth_code.create_token_response(request, token_handler)

    def validate_authorization_request(self, request):
        """Validates the OpenID Connect authorization request parameters.

        :returns: (list of scopes, dict of request info)
        """
        # If request.prompt is 'none' then no login/authorization form should
        # be presented to the user. Instead, a silent login/authorization
        # should be performed.
        if request.prompt == 'none':
            raise OIDCNoPrompt()
        else:
            return self.auth_code.validate_authorization_request(request)

    def validate_token_request(self, request):
        return self.auth_code.validate_token_request(request)


class OpenIDConnectImplicit(OpenIDConnectBase):

    def __init__(self, request_validator=None):
        self.request_validator = request_validator or RequestValidator()
        super(OpenIDConnectImplicit, self).__init__(
            request_validator=self.request_validator)
        self.implicit = ImplicitGrant(
            request_validator=request_validator)
        self.implicit.register_response_type('id_token')
        self.implicit.register_response_type('id_token token')
        self.implicit.register_authorization_validator(
            self.openid_authorization_validator)
        self.implicit.register_authorization_validator(
            self.openid_implicit_authorization_validator)
        self.implicit.register_token_modifier(self.add_id_token)

    def create_authorization_response(self, request, token_handler):
        return self.create_token_response(request, token_handler)

    def create_token_response(self, request, token_handler):
        return self.implicit.create_authorization_response(
            request, token_handler)

    def validate_authorization_request(self, request):
        """Validates the OpenID Connect authorization request parameters.

        :returns: (list of scopes, dict of request info)
        """
        # If request.prompt is 'none' then no login/authorization form should
        # be presented to the user. Instead, a silent login/authorization
        # should be performed.
        if request.prompt == 'none':
            raise OIDCNoPrompt()
        else:
            return self.implicit.validate_authorization_request(request)


class OpenIDConnectHybrid(OpenIDConnectBase):

    def __init__(self, request_validator=None):
        self.request_validator = request_validator or RequestValidator()

        self.auth_code = AuthorizationCodeGrant(
            request_validator=request_validator)
        self.auth_code.register_response_type('code id_token')
        self.auth_code.register_response_type('code token')
        self.auth_code.register_response_type('code id_token token')
        self.auth_code.register_authorization_validator(
            self.openid_authorization_validator)
        self.auth_code.register_code_modifier(self.add_token)
        self.auth_code.register_code_modifier(self.add_id_token)
        self.auth_code.register_token_modifier(self.add_id_token)

    @property
    def refresh_token(self):
        return self.auth_code.refresh_token

    @refresh_token.setter
    def refresh_token(self, value):
        self.auth_code.refresh_token = value

    def create_authorization_code(self, request):
        return self.auth_code.create_authorization_code(request)

    def create_authorization_response(self, request, token_handler):
        return self.auth_code.create_authorization_response(
            request, token_handler)

    def create_token_response(self, request, token_handler):
        return self.auth_code.create_token_response(request, token_handler)

    def validate_authorization_request(self, request):
        """Validates the OpenID Connect authorization request parameters.

        :returns: (list of scopes, dict of request info)
        """
        # If request.prompt is 'none' then no login/authorization form should
        # be presented to the user. Instead, a silent login/authorization
        # should be performed.
        if request.prompt == 'none':
            raise OIDCNoPrompt()
        else:
            return self.auth_code.validate_authorization_request(request)

    def validate_token_request(self, request):
        return self.auth_code.validate_token_request(request)

