=============
Device
=============

The device endpoint is used to initiate the authorization flow by requesting a set of
verification codes from the authorization server by making an HTTP "POST" request to
the device authorization endpoint.

** Device Authorization Request **
    The client makes a device authorization request to the device
    authorization endpoint by including the following parameters using
    the "application/x-www-form-urlencoded" format:

    POST /device_authorization HTTP/1.1
    Host: server.example.com
    Content-Type: application/x-www-form-urlencoded
    client_id=123456&scope=example_scope

.. code-block:: python

    # Initial setup
    from your_validator import your_validator
    verification_uri = "https://example.com/device"

    def user_code():
       # some logic to generate a random string...
       return "123-456"

    # user code is optional
    server = DeviceApplicationServer(your_validator, verification_uri, user_code)

    headers, data, status = server.create_device_authorization_response(request)

     # response from /device_authorization endpoint on your server
    from your_framework import http_response
    http_response(data, status=status, headers=headers)



.. code-block:: python

    # example response
    {
        "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
        "user_code": "123-456",
        "verification_uri": "https://example.com/device",
        "verification_uri_complete":
            "https://example.com/device?user_code=WDJB-MJHT",
        "expires_in": 1800,
        "interval": 5
    }


.. autoclass:: oauthlib.oauth2.DeviceAuthorizationEndpoint
    :members:
