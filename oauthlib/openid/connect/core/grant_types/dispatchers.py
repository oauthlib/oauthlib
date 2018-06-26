import logging
log = logging.getLogger(__name__)


class AuthorizationCodeGrantDispatcher(object):
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


class ImplicitTokenGrantDispatcher(object):
    """
    This is an adapter class that will route simple Authorization Code requests, those that have response_type=code and a scope
    including 'openid' to either the default_auth_grant or the oidc_auth_grant based on the scopes requested.
    """
    def __init__(self, default_implicit_grant=None, oidc_implicit_grant=None):
        self.default_implicit_grant = default_implicit_grant
        self.oidc_implicit_grant = oidc_implicit_grant

    def _handler_for_request(self, request):
        handler = self.default_implicit_grant

        if request.scopes and "openid" in request.scopes and 'id_token' in request.response_type:
            handler = self.oidc_implicit_grant

        log.debug('Selecting handler for request %r.', handler)
        return handler

    def create_authorization_response(self, request, token_handler):
        return self._handler_for_request(request).create_authorization_response(request, token_handler)

    def validate_authorization_request(self, request):
        return self._handler_for_request(request).validate_authorization_request(request)


class AuthorizationTokenGrantDispatcher(object):
    """
    This is an adapter class that will route simple Token requests, those that authorization_code have a scope
    including 'openid' to either the default_token_grant or the oidc_token_grant based on the scopes requested.
    """
    def __init__(self, request_validator, default_token_grant=None, oidc_token_grant=None):
        self.default_token_grant = default_token_grant
        self.oidc_token_grant = oidc_token_grant
        self.request_validator = request_validator

    def _handler_for_request(self, request):
        handler = self.default_token_grant
        scopes = ()
        parameters = dict(request.decoded_body)
        client_id = parameters.get('client_id', None)
        code = parameters.get('code', None)
        redirect_uri = parameters.get('redirect_uri', None)

        # If code is not pressent fallback to `default_token_grant` wich will
        # raise an error for the missing `code` in `create_token_response` step.
        if code:
            scopes = self.request_validator.get_authorization_code_scopes(client_id, code, redirect_uri, request)

        if 'openid' in scopes:
            handler = self.oidc_token_grant

        log.debug('Selecting handler for request %r.', handler)
        return handler

    def create_token_response(self, request, token_handler):
        handler = self._handler_for_request(request)
        return handler.create_token_response(request, token_handler)
