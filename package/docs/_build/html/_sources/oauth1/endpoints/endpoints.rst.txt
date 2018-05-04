Provider endpoints
==================

Each endpoint is responsible for one step in the OAuth 1 workflow. They can be
used either independently or in a combination. They depend on the use of a
:doc:`../validator`.

See :doc:`../preconfigured_servers` for available composite endpoints/servers.

.. toctree::
    :maxdepth: 2

    request_token
    authorization
    access_token
    resource
    signature_only
