"""
oauthlib.oauth2.rfc6749
~~~~~~~~~~~~~~~~~~~~~~~

This module is an implementation of various logic needed
for consuming and providing OAuth 2.0 RFC6749.
"""
import json

from oauthlib.common import generate_token

from oauthlib.oauth2.rfc6749.endpoints.base import (
    BaseEndpoint,
    catch_errors_and_unavailability,
)


class DeviceAuthorizationEndpoint(BaseEndpoint):

    """DeviceAuthorization endpoint - used by the client to initiate
    the authorization flow by requesting a set of verification codes
    from the authorization server by making an HTTP "POST" request to
    the device authorization endpoint.

    The client authentication requirements of Section 3.2.1 of [RFC6749]
    apply to requests on this endpoint, which means that confidential
    clients (those that have established client credentials) authenticate
    in the same manner as when making requests to the token endpoint, and
    public clients provide the "client_id" parameter to identify
    themselves.
    """

    def __init__(
        self,
        verification_uri,
        expires_in=1800,
        interval=None,
        verification_uri_complete=None,
    ):
        """
        :param verification_uri: a string containing the URL that can be polled by the client application
        :param expires_in: a number that represents the lifetime of the `user_code` and `device_code`
        :param interval: an option number that represents the number of seconds between each poll requests
        :param verification_uri_complete: a string of a function that can be called with `user_data` as parameter
        """
        self._expires_in = expires_in
        self._interval = interval
        self._verification_uri = verification_uri
        self._verification_uri_complete = verification_uri_complete
        self._interval = interval

        BaseEndpoint.__init__(self)

    @property
    def interval(self):
        """The minimum amount of time in seconds that the client
        SHOULD wait between polling requests to the token endpoint.  If no
        value is provided, clients MUST use 5 as the default.
        """
        return self._interval

    @property
    def expires_in(self):
        """The lifetime in seconds of the "device_code" and "user_code"."""
        return self._expires_in

    @property
    def verification_uri(self):
        """The end-user verification URI on the authorization
        server.  The URI should be short and easy to remember as end users
        will be asked to manually type it into their user agent.
        """
        return self._verification_uri

    def verification_uri_complete(self, user_code):
        if not self._verification_uri_complete:
            return None
        if isinstance(self._verification_uri_complete, str):
            return self._verification_uri_complete.format(user_code=user_code)
        if callable(self._verification_uri_complete):
            return self._verification_uri_complete(user_code)
        return None

    @catch_errors_and_unavailability
    def create_device_authorization_response(self, uri):
        """create_device_authorization_response - generates a unique device
        verification code and an end-user code that are valid for a limited
        time and includes them in the HTTP response body using the
        "application/json" format [RFC8259] with a 200 (OK) status code, as
        described in `Section-3.2`_.

        :param uri: a string representing the current parameter.
        :return: the response payload as a JSON string.

        The response contains the following parameters:

        device_code
           REQUIRED.  The device verification code.

        user_code
           REQUIRED.  The end-user verification code.

        verification_uri
           REQUIRED.  The end-user verification URI on the authorization
           server.  The URI should be short and easy to remember as end users
           will be asked to manually type it into their user agent.

        verification_uri_complete
           OPTIONAL.  A verification URI that includes the "user_code" (or
           other information with the same function as the "user_code"),
           which is designed for non-textual transmission.

        expires_in
           REQUIRED.  The lifetime in seconds of the "device_code" and
           "user_code".

        interval
           OPTIONAL.  The minimum amount of time in seconds that the client
           SHOULD wait between polling requests to the token endpoint.  If no
           value is provided, clients MUST use 5 as the default.

        For example:

           HTTP/1.1 200 OK
           Content-Type: application/json
           Cache-Control: no-store

           {
             "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
             "user_code": "WDJB-MJHT",
             "verification_uri": "https://example.com/device",
             "verification_uri_complete":
                 "https://example.com/device?user_code=WDJB-MJHT",
             "expires_in": 1800,
             "interval": 5
           }

        .. _`Section-3.2`: https://www.rfc-editor.org/rfc/rfc8628#section-3.2
        """
        headers = {}
        user_code = generate_token()
        data = {
            "verification_uri": self.verification_uri,
            "expires_in": self.expires_in,
            "user_code": user_code,
            "device_code": generate_token(),
        }
        if self.interval is not None:
            data["interval"] = self.interval

        verification_uri_complete = self.verification_uri_complete(user_code)
        if verification_uri_complete:
            data["verification_uri_complete"] = verification_uri_complete

        body = json.dumps(data)
        return headers, body, 200
