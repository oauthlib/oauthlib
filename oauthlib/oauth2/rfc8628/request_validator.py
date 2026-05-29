from oauthlib.oauth2 import RequestValidator as OAuth2RequestValidator


class RequestValidator(OAuth2RequestValidator):
    def client_authentication_required(self, request, *args, **kwargs):
        """Determine if client authentication is required for current request.

        According to the rfc8628, client authentication is required in the following cases:
            - Device Authorization Request follows the, the client authentication requirements
              of Section 3.2.1 of [RFC6749] apply to requests on this endpoint, which means that
              confidential clients (those that have established client credentials) authenticate
              in the same manner as when making requests to the token endpoint, and
              public clients provide the "client_id" parameter to identify themselves,
              see `Section 3.1`_.

        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :rtype: True or False

        Method is used by:
            - Device Authorization Request

        .. _`Section 3.1`: https://www.rfc-editor.org/rfc/rfc8628#section-3.1
        """
        return True

    def validate_device_code(self, client_id, code, request, *args, **kwargs):
        """Validate a ``device_code`` and return its authorization status.

        Called when a device polls the token endpoint. The implementation
        should look up the ``device_code``, confirm it was issued to the
        authenticating client, and report where it is in the authorization
        process described in `Section 3.5`_ by returning one of the
        ``DeviceCodeGrant`` status constants:

        - ``DEVICE_CODE_AUTHORIZED``: the end user approved the request.
          The implementation should also set ``request.user`` (and any
          scopes or claims to embed) so they end up on the issued token,
          which removes the need for a separate token validator.
        - ``DEVICE_CODE_PENDING``: the user has not yet completed the
          interaction; raises ``AuthorizationPendingError``.
        - ``DEVICE_CODE_SLOW_DOWN``: as pending, but the client is polling
          too quickly; raises ``SlowDownError``.
        - ``DEVICE_CODE_EXPIRED``: the ``device_code`` has expired; raises
          ``ExpiredTokenError``.
        - ``DEVICE_CODE_DENIED``: the user denied the request; raises
          ``AccessDenied``.

        Returning ``None`` (or any unrecognized value) is treated as an
        unknown or invalid ``device_code`` and raises ``InvalidGrantError``.

        :param client_id: Unicode client identifier.
        :param code: Unicode device_code.
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :rtype: str or None

        Method is used by:
            - Device Code Grant

        .. _`Section 3.5`: https://www.rfc-editor.org/rfc/rfc8628#section-3.5
        """
        raise NotImplementedError("Subclasses must implement this method.")
