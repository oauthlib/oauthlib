import enum
import json
import datetime
from datetime import timedelta

from oauthlib.oauth2 import RequestValidator, Server, DeviceApplicationServer
from oauthlib.oauth2.rfc8628 import errors as device_flow_errors
from oauthlib.oauth2.rfc8628.errors import AccessDenied, AuthorizationPendingError, ExpiredTokenError, SlowDownError


"""
A pseudocode implementation of the device flow code under an Oauth2 provider.

This example is not concerned with openid in any way.

This example is also not a 1:1 pseudocode implementation. Please refer to the rfc
for the full details.
https://datatracker.ietf.org/doc/html/rfc8628

This module is just acting as a way to demonstrate the main pieces
needed in oauthlib to implement the flow


We also assume you already have the /token & /login endpoint in your provider.

Your provider will also need the following endpoints(which will be discussed
in the example below):
  - /device_authorization (part of rfc)
  - /device (part of rfc)
  - /approve-deny (up to your implementation, this is an example)
"""


"""
Device flow pseudocode implementation step by step:
    0. Providing some way to represent the device flow session

    Some python object to represent the current state of the device during
    the device flow. This, for example, could be an object that persists
    and represents the device in a database
"""


class Device:
    class DeviceFlowStatus(enum.Enum):
        AUTHORIZED = "Authorized"
        AUTHORIZATION_PENDING = "Authorization_pending"
        EXPIRED = "Expired"
        DENIED = "Denied"

    # https://datatracker.ietf.org/doc/html/rfc8628#section-3.2
    # https://datatracker.ietf.org/doc/html/rfc8628#section-3.4
    id = ...  # if Device is representing a database object, this will be the id of that row
    device_code = ...
    user_code = ...
    scope = ...
    interval = ...  # in seconds, default is 5
    expires = ...  # seconds
    status = ...  # DeviceFlowStatus with AUTHORIZATION_PENDING as the default

    client_id = ...
    last_checked = ...  # datetime


"""
    1. User goes on their device(client) and the client sends a request to /device_authorization
    against the provider:
    https://datatracker.ietf.org/doc/html/rfc8628#section-3.1
    https://datatracker.ietf.org/doc/html/rfc8628#section-3.2


    POST /device_authorization HTTP/1.1
      Host: server.example.com
      Content-Type: application/x-www-form-urlencoded

      client_id=1406020730&scope=example_scope

      Response:
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
"""


class DeviceAuthorizationEndpoint:
    @staticmethod
    def create_device_authorization_response(request):
        server = DeviceApplicationServer(interval=5, verification_uri="https://example.com/device")
        return server.create_device_authorization_response(request)

    def post(self, request):
        headers, data, status = self.create_device_authorization_response(request)
        device_response = ...

        # Create an instance of examples.device_flow.Device` using `request` and `data`that encapsulates
        # https://datatracker.ietf.org/doc/html/rfc8628#section-3.1 &
        # https://datatracker.ietf.org/doc/html/rfc8628#section-3.2

        return device_response


"""
    2. Client presents the information to the user
    (There's a section on non visual capable devices as well
    https://datatracker.ietf.org/doc/html/rfc8628#section-5.7)
          +-------------------------------------------------+
            |                                                 |
            |  Scan the QR code or, using     +------------+  |
            |  a browser on another device,   |[_]..  . [_]|  |
            |  visit:                         | .  ..   . .|  |
            |  https://example.com/device     | . .  . ....|  |
            |                                 |.   . . .   |  |
            |  And enter the code:            |[_]. ... .  |  |
            |  WDJB-MJHT                      +------------+  |
            |                                                 |
            +-------------------------------------------------+
"""
# The implementation for step 2 is up to the owner of device.


""""
    3 (The browser flow). User goes to https://example.com/device where they're presented with a
    form to fill in the user code.

    Implement that endpoint on your provider and follow the logic in the rfc.

    Making use of the errors in `oauthlib.oauth2.rfc8628.errors`

    raise AccessDenied/AuthorizationPendingError/ExpiredTokenError where appropriate making use of
    `examples.device_flow.Device` to get and update current state of the device during the session

    If the user isn't logged in(after inputting the user-code), they should be redirected to the provider's /login
    endpoint and redirected back to an /approve-deny endpoint(The name and implementation of /approve-deny is up
    to the owner of the provider, this is just an example).
    They should then see an "approve" or "deny" button to authorize the device.

    Again, using `examples.device_flow.Device` to update the status appropriately during the session.
"""
# /device and /approve-deny is up to the owner of the provider to implement. Again, make sure to
# keep referring to the rfc when implementing.


"""
4 (The polling flow)
    https://datatracker.ietf.org/doc/html/rfc8628#section-3.4
    https://datatracker.ietf.org/doc/html/rfc8628#section-3.5


    Right after step 2, the device polls the /token endpoint every "interval" amount of seconds
    to check if user has approved or denied the request.

    When grant type is `urn:ietf:params:oauth:grant-type:device_code`,
    `oauthlib.oauth2.rfc8628.grant_types.device_code.DeviceCodeGrant` will be the handler
    that handles token generation.
"""


# This is purely for illustrative purposes
# to demonstrate rate limiting on the token endpoint for the device flow.
# It is up to as the provider to decide how you want
# to rate limit the device during polling.
def rate_limit(func, rate="1/5s"):
    def wrapper():
        # some logic to ensure client device is rate limited by a minimum
        # of 1 request every 5 seconds during device polling
        # https://datatracker.ietf.org/doc/html/rfc8628#section-3.2

        # use device_code to retrieve device
        device = Device

        # get the time in seconds since the device polled the /token endpoint
        now = datetime.datetime.now(tz=datetime.UTC)
        diff = now - timedelta(device.last_checked)
        total_seconds_since_last_device_poll = diff.total_seconds()

        device.last_checked = now

        # for illustrative purposes. 1/5s means 1 request every 5 seconds.
        # so if `total_seconds_since_last_device_poll` is 4 seconds, this will
        # raise an error
        if total_seconds_since_last_device_poll < rate:
            raise device_flow_errors.SlowDownError()

        result = func()
        return result

    return wrapper


class ExampleRequestValidator(RequestValidator):
    # All the other methods that need to be implemented...
    # see examples.skeleton_oauth2_web_application_server.SkeletonValidator
    # for a more complete example.

    # Here our main concern is this method:
    def create_token_response(self): ...


class ServerSetupForTokenEndpoint:
    def __init__(self):
        validator = ExampleRequestValidator
        self.server = Server(validator)


# You should already have the /token endpoint implemented in your provider.
class TokenEndpoint(ServerSetupForTokenEndpoint):
    def default_flow_token_response(self, request):
        url, headers, body, status = self.server.create_token_response(request)
        access_token = json.loads(body).get("access_token")

        # return access_token in a http response
        return access_token

    @rate_limit  # this will raise the SlowDownError
    def device_flow_token_response(self, request, device_code):
        """
        Following the rfc, this will route the device request accordingly and raise
        required errors.

        Remember that unlike other auth flows, the device if polling this endpoint once
        every "interval" amount of seconds.
        """
        # using device_code arg to retrieve the correct device object instance
        device = Device

        if device.status == device.DeviceFlowStatus.AUTHORIZATION_PENDING:
            raise AuthorizationPendingError()

        # If user clicked "deny" in the /approve-deny page endpoint.
        # the device gets set to 'authorized' in /approve-deny and /device checks
        # if someone tries to input a code for a user code that's already been authorized
        if device.status == device.DeviceFlowStatus.DENIED:
            raise AccessDenied()

        url, headers, body, status = self.server.create_token_response(request)

        access_token = json.loads(body).get("access_token")

        device.status = device.EXPIRED

        # return access_token in a http response
        return access_token

    # Example of how token endpoint could handle the token creation depending on
    # the grant type during a POST to /token.
    def post(self, request):
        params = request.POST
        if params.get("grant_type") == "urn:ietf:params:oauth:grant-type:device_code":
            return self.device_flow_token_response(request, params["device_code"])
        return self.default_flow_token_response(request)
