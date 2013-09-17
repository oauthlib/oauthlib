================
Token revocation
================

Revocation endpoints invalidate access and refresh tokens upon client request.
They are commonly part of the authorization endpoint.

.. code-block:: python

    # Initial setup
    from your_validator import your_validator
    server = WebApplicationServer(your_validator)

    # Token revocation
    uri = 'https://example.com/revoke_token'
    headers, body, http_method = {}, 'token=sldafh309sdf', 'POST'

    headers, body, status = server.create_revocation_response(uri,
        headers=headers, body=body, http_method=http_method)

    from your_framework import http_response
    http_response(body, status=status, headers=headers)


.. autoclass:: oauthlib.oauth2.RevocationEndpoint
    :members:
