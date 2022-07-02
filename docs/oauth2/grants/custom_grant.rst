=================
Custom Grant type
=================

Writing a custom grant type can be useful to implement a specification
which is in an early draft, or implement a grant provided by a
specific OAuth2.0 Authorization Server documentation but not provided
by oauthlib. For information, any grant types with a clear
specification can be integrated in oauthlib, just make a PR for that !
See :doc:`how to contribute here </contributing>`.

Please find how to create a new grant and use it in an endpoint:

.. contents:: Tutorial Contents
    :depth: 3


1. Define your Grant Type
-------------------------
The heart of your code is done by subclassing
:py:class:`GrantTypeBase`.  If you want to use it in the Authorize
endpoint, you will have to implement
:py:meth:`create_authorization_response`, if you want to use the Token
endpoint, implement :py:meth:`create_token_response`. You can also
implement both.

2. Implement the grant
----------------------
Inside the method's implementation, you will have to:

* add validations of the request (syntax, parameters, ...)
* call and orchestrate one or multiple Request Validators calls
* generate and return HTTP response

You can define new Request Validator methods if needed, or reuse the
existing ones.

3. Associate it with Endpoints
------------------------------
Then, once implemented, you have to instantiate the grant object and
bind it to your endpoint. Either :py:class:`AuthorizationEndpoint`,
:py:class:`TokenEndpoint` or both.

4. Example
----------
This example shows how to add a simple extension to the `Token endpoint`:

* creation of a new class ``MyCustomGrant``, and implement ``create_token_response``.
* do basics and custom request validations, then call a custom method
  of `Request Validator` to extend the interface for the implementor.
* instantiate the new grant, and bind it with an existing ``Server``.

.. code-block:: python

    grant_name = 'urn:ietf:params:oauth:grant-type:my-custom-grant'

    class MyCustomGrant(GrantTypeBase):
        def create_token_response(self, request, token_handler):
            if not request.grant_type == grant_name:
                raise errors.UnsupportedGrantTypeError(request=request)

            # implement your custom validation checks
            # ..
            self.request_validator.your_custom_check(request)

            token = token_handler.create_token(request)
            return self._get_default_headers(), json.dumps(token), 200

    def setup_oauthlib():
        my_custom_grant = MyCustomGrant()
        server = Server(request_validator)
        server.grant_types[grant_name] = my_custom_grant


You can find concrete examples directly in the code source of existing
grants and existing servers. See Grant Types in
:py:mod:`oauthlib.oauth2.rfc749.grant_types`, and Servers in
:py:mod:`oauthlib.oauth2.rfc749.endpoints.pre_configured`
