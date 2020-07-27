===================
Metadata endpoint
===================

OAuth2.0 Authorization Server Metadata (`RFC8414`_) endpoint provide the metadata of your authorization server. Since the metadata results can be a combination of OAuthlib's Endpoint (see :doc:`/oauth2/preconfigured_servers`), the MetadataEndpoint's class takes a list of Endpoints in parameter, and aggregate the metadata in the response.

See below an example of usage with `bottle-oauthlib`_ when using a `LegacyApplicationServer` (password grant) endpoint:

.. code-block:: python

    import bottle
    from bottle_oauthlib.oauth2 import BottleOAuth2
    from oauthlib import oauth2

    app = bottle.Bottle()
    app.authmetadata = BottleOAuth2(app)

    oauthlib_server = oauth2.LegacyApplicationServer(oauth2.RequestValidator())
    app.authmetadata.initialize(oauth2.MetadataEndpoint([oauthlib_server], claims={
        "issuer": "https://xx",
        "token_endpoint": "https://xx/token",
        "revocation_endpoint": "https://xx/revoke",
        "introspection_endpoint": "https://xx/tokeninfo"
    }))


    @app.get('/.well-known/oauth-authorization-server')
    @app.authmetadata.create_metadata_response()
    def metadata():
        pass


    if __name__ == "__main__":
        app.run()  # pragma: no cover


Sample response's output:


.. code-block:: javascript

    $ curl -s http://localhost:8080/.well-known/oauth-authorization-server|jq .
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
.. _`bottle-oauthlib`: https://github.com/thomsonreuters/bottle-oauthli
