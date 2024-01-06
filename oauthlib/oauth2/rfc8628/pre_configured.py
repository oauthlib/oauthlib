from oauthlib.oauth2.rfc8628.endpoints.device_authorization import (
    DeviceAuthorizationEndpoint,
)


class DeviceApplicationServer(DeviceAuthorizationEndpoint):

    """An all-in-one endpoint featuring Authorization code grant and Bearer tokens."""

    def __init__(self, request_validator, verification_uri, **kwargs):
        """Construct a new web application server.

        :param request_validator: An implementation of
                                  oauthlib.oauth2.rfc8626.RequestValidator.
        :param verification_uri: the verification_uri to be send back.
        """
        DeviceAuthorizationEndpoint.__init__(
            self, request_validator, verification_uri=verification_uri
        )
