===================
Metadata endpoint
===================

OAuth2.0 Authorization Server Metadata (`RFC8414`_) endpoint provide the metadata of your authorization server. Since the metadata results can be a combination of OAuthlib's Endpoint (see :doc:`/oauth2/preconfigured_servers`), the MetadataEndpoint's class takes a list of Endpoints in parameter, and aggregate the metadata in the response.

See below an example of usage with `FastAPI`_ when using a `LegacyApplicationServer` (password grant) endpoint. ``create_metadata_response`` is a coroutine and must be awaited:

.. code-block:: python

    from fastapi import FastAPI, Request
    from fastapi.responses import Response
    from oauthlib import oauth2

    app = FastAPI()

    oauthlib_server = oauth2.LegacyApplicationServer(oauth2.RequestValidator())
    metadata_endpoint = oauth2.MetadataEndpoint([oauthlib_server], claims={
        "issuer": "https://xx",
        "token_endpoint": "https://xx/token",
        "revocation_endpoint": "https://xx/revoke",
        "introspection_endpoint": "https://xx/tokeninfo"
    })


    @app.get('/.well-known/oauth-authorization-server')
    async def metadata(request: Request):
        headers, body, status = await metadata_endpoint.create_metadata_response(
            str(request.url), request.method, None, dict(request.headers))
        return Response(content=body, status_code=status, headers=headers)


Sample response's output:


.. code-block:: javascript

    $ curl -s http://localhost:8000/.well-known/oauth-authorization-server|jq .
    {
      "issuer": "https://xx",
      "token_endpoint": "https://xx/token",
      "revocation_endpoint": "https://xx/revoke",
      "introspection_endpoint": "https://xx/tokeninfo",
      "grant_types_supported": [
        "password",
        "refresh_token"
      ],
      "token_endpoint_auth_methods_supported": [
        "client_secret_post",
        "client_secret_basic"
      ],
      "revocation_endpoint_auth_methods_supported": [
        "client_secret_post",
        "client_secret_basic"
      ],
      "introspection_endpoint_auth_methods_supported": [
        "client_secret_post",
        "client_secret_basic"
      ]
    }


.. autoclass:: oauthlib.oauth2.MetadataEndpoint
    :members:


.. _`RFC8414`: https://tools.ietf.org/html/rfc8414
.. _`FastAPI`: https://fastapi.tiangolo.com/
