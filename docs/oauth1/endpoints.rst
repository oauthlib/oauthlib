Provider endpoints
==================

Each endpoint is responsible for one step in the OAuth 1 workflow. They can be
used either independently or in a combination. They depend on the use of a
:doc:`validator`.

See :doc:`preconfigured_servers` for available composite endpoints/servers.

.. autoclass:: oauthlib.oauth1.AuthorizationEndpoint
    :members:

.. autoclass:: oauthlib.oauth1.AccessTokenEndpoint
    :members:

.. autoclass:: oauthlib.oauth1.RequestTokenEndpoint
    :members:

.. autoclass:: oauthlib.oauth1.ResourceEndpoint
    :members:
