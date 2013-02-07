# -*- coding: utf-8 -*-
============================
Creating an OAuth 2 provider
============================

Note that OAuth 2 provider is still very much a work in progress, consider it a preview of a near future =) Feedback in any form much welcome!

A high level overview
---------------------

OAuth 2 is a very generic set of documents that leave a lot up to the implementer. It is not even a protocol, it is a framework. OAuthLib approaches this by separating the logic into three categories, endpoints, grant types and tokens.

Endpoints
~~~~~~~~~

There are three different endpoints, the authorization endpoint which mainly handles user authorization, the token endpoint which provides tokens and the resource endpoint which provides access to protected resources. It is to the endpoints you will feed requests and get back an almost complete response. This process is simplified for you using a decorator such as the django one described later. 

The main purpose of the endpoint in OAuthLib is to figure out which grant type or token to dispatch the request to.

Grant types
~~~~~~~~~~~

Grant types are what make OAuth 2 so flexible. The Authorization Code grant is very similar to OAuth 1 (with less crypto), the Implicit grant serves less secure applications such as mobile applications, the Resource Owner Password Credentials grant allows for legacy applications to incrementally transition to OAuth 2, the Client Credentials grant is excellent for embedded services and backend applications. 

The main purpose of the grant types is to authorize access to protected resources in various ways with different security credentials.

Naturally, OAuth 2 allows for extension grant types to be defined and OAuthLib attempts to cater for easy inclusion of this as much as possible. 

Certain grant types allow the issuing of refresh tokens which will allow a client to request new tokens for as long as you as provider allow them too. In general, OAuth 2 tokens should expire quickly and rather than annoying the user by require them to go through the authorization redirect loop you may use the refresh token to get a new access token. Refresh tokens, contrary to what their name suggest, are components of a grant type rather than token types (like Bearer tokens), much like the authorization code in the authorization code grant.

Tokens
~~~~~~

The main token type of OAuth 2 is Bearer tokens and that is what OAuthLib currently supports. Other tokens, such as JWT, SAML and possibly MAC (if the spec matures) can easily be added (and will be in due time).

The purpose of a token is to authorize access to protected resources to a client (i.e. your G+ feed).


How do I develop an OAuth 2 provider?
-------------------------------------

The majority of the work involves mapping various validation and persistence methods to a storage backend. The not very accurately named interface you will need to implement is called a RequestValidator (name suggestions welcome).

The request validator can be found in oauthlib.oauth2.draft25.grant_types, which will be the main source of documentation on which methods you need to implement. As an example, a very basic validate_client_id method might be implemented in Django as follows::

    from oauthlib.oauth2 import RequestValidator

    from my_models import Client

    class MyRequestValidator(RequestValidator):

        def validate_client_id(self, client_id, request):
            try:
                Client.objects.get(client_id=client_id)
                return True
            except Client.DoesNotExist:
                return False


Pre configured endpoints
------------------------

OAuthLib provide a number of configured all-in-one endpoints (auth + token + resource) with different grant types, all utilize Bearer tokens. The available configurations are

* WebApplicationServer featuring Authorization Code Grant and Refresh Tokens
* MobileApplicationServer featuring Implicit Grant
* LegacyApplicationServer featuring Resource Owner Password Credentials Grant and Refresh Tokens
* BackendApplicationServer featuring Client Credentials Grant
* Server featuring all above bundled into one


Using the django decorator
--------------------------

Assuming you have the validator from above implemented already, creating an OAuth 2 provider can be as simple as::

    # your_views.py
    from my_validator import MyRequestValidator
    
    from oauthlib.oauth2 import WebApplicationServer   # BearerTokens + Authorization Code grant
    from oauthlib.oauth2.ext.django import OAuth2ProviderDecorator
    
    validator = MyRequestValidator()
    server = WebApplicationServer(validator)
    provider = OAuth2ProviderDecorator('/error', server)    # See view error below
    
    @login_required
    @provider.pre_authorization_view
    def authorize(request, scopes=None):
        # This is the traditional authorization page
        # Scopes will be the list of scopes client requested access too
        # You will want to present them in a nice form where the user can
        # select which scopes they allow the client to access.
        return render(request, 'authorize.html', {'scopes': scopes})


    @login_required
    @provider.post_authorization_view
    def authorization_response(request):
        # This is where the form submitted from authorize should end up
        # Which scopes user authorized access to + extra credentials you want
        # appended to the request object passed into the validator methods
        return request.POST['scopes'], {}


    @provider.access_token_view
    def token_response(request):
        # Not much too do here for you, return a dict with extra credentials
        # you want appended to request.credentials passed to the save_bearer_token
        # method of the validator.
        return {'extra': 'creds'}


    @provider.protected_resource_view(scopes=['images'])
    def i_am_protected(request, client, resource_owner, **kwargs):
        # One of your many OAuth 2 protected resource views, returns whatever you fancy
        # May be bound to various scopes of your choosing
        return HttpResponse('pictures of cats')


    def error(request):
        # The /error page users will be redirected to if there was something
        # wrong with the credentials the client included when redirecting the
        # user to the authorization form. Mainly if the client was invalid or
        # included a malformed / invalid redirect url.
        # Error and description can be found in GET['error'] and GET['error_description']
        return HttpResponse('Bad client! Warn user!')


Can you please add X, Y and Z?
------------------------------

If these include dashboards, database migrations, registration APIs and similar the answer is no. While these would be excellent to have, oauthlib is not the place for them. I would much rather see a django middleware plugin with these features but I currently lack the time to develop it myself.

Creating decorators for other frameworks
----------------------------------------

Hopefully, it should be quite straightforward to port the django decorator to other web frameworks as the decorator mainly provide a means for translating the framework specific request object into uri, http_method, headers and body.


How do I enable logging?
------------------------
OAuthLib can provide valuable debug logs that help you get your provider up and running much quicker. You can log to stdout for example using::

    import logging
    log = logging.getLogger('oauthlib')
    log.setLevel(logging.DEBUG)

