===================
Token introspection
===================

Introspect endpoints read opaque access and/or refresh tokens upon client
request. Also known as tokeninfo.

.. code-block:: python

    # Initial setup
    from your_validator import your_validator
    server = WebApplicationServer(your_validator)

    async def introspect():
        # Token introspection
        uri = 'https://example.com/introspect'
        headers, body, http_method = {}, 'token=sldafh309sdf', 'POST'

        headers, body, status = await server.create_introspect_response(uri,
            headers=headers, body=body, http_method=http_method)

        from your_framework import http_response
        return http_response(body, status=status, headers=headers)


.. autoclass:: oauthlib.oauth2.IntrospectEndpoint
    :members:
