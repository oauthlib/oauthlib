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

    # verification_uri_complete can either be a callable that receives user code as an arg
    # or a string (e.g verification_uri_complete = "https://example.com/device=1234")
    verification_uri_complete = lambda user_code: f"https://example.com/device={user_code}"

    def user_code():
       # some logic to generate a random string...
       return "123-456"

    # user code is optional
    server = DeviceApplicationServer(
        request_validator=your_validator,
        verification_uri=verification_uri,
        verification_uri_complete=verification_uri_complete,
        user_code=user_code
    )

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
        "interval": 5,
        "scope": "example_scope"
    }

The ``scope`` key is not part of RFC 8628. It holds the scopes resolved for the
request — either what the device asked for or what ``get_default_scopes``
returned — so you can persist them alongside the ``device_code`` and
``user_code``. It is omitted when no scopes were resolved.


.. autoclass:: oauthlib.oauth2.DeviceAuthorizationEndpoint
    :members:
