=================
Custom Grant type
=================

Writing a custom grant type can be useful to implement a specification
which is in an early draft, or implement a grant provided by a
specific OAuth2.0 Authorization Server documentation but not provided
by oauthlib. For information, any grant types with a clear
specification can be integrated in oauthlib, just make a PR for that
!. See :doc:`how to contribute here </contributing>`.

Please find below an example of how to create a new grant and use it
in an endpoint:

.. contents:: Tutorial Contents
    :depth: 3


1. Define your Grant Type
-------------------------

The heart of your code is done by subclassing
:py:class:`oauthlib.oauth2.rfc6749.grant_types.base.GrantTypeBase`.
If you want to use it in the Authorize endpoint, you will have to
implement `create_authorization_response`, if in the Token endpoint,
implement `create_token_response`.


2. Associate it with Endpoints
------------------------------
Then, once declared, you have to create an instance of your grant and
add it to your
endpoint. I.e. :py:class:`oauthlib.oauth2.rfc6749.endpoints.AuthorizationEndpoint`
or :py:class:`oauthlib.oauth2.rfc6749.endpoints.TokenEndpoint`. You
can see concrete examples in
:py:class:`oauthlib.oauth2.rfc6749.endpoints.pre_configured.Server`
for examples.

3. Example
----------

Sample below shows the creation of a new custom `grant_type` parameter
and declare it in the `/token` endpoint of your `Server`. Note that
you can reuse `pre_configured.Server` or use your own class inheriting
of the `Endpoint` classes you have decided.

.. code-block:: python

    class MyCustomGrant(GrantTypeBase):
        def create_token_response(self, request, token_handler):
            if not request.grant_type == 'urn:ietf:params:oauth:grant-type:my-custom-grant':
                raise errors.UnsupportedGrantTypeError(request=request)
            # implement your custom validation checks
            # ..

            token = token_handler.create_token(request,
                                               refresh_token=self.issue_new_refresh_tokens)
            return self._get_default_headers(), json.dumps(token), 200

    def setup_oauthlib():
        my_custom_grant = MyCustomGrant()
        server = Server(request_validator)
        server.grant_types["urn:ietf:params:oauth:grant-type:my-custom-grant"] = my_custom_grant
