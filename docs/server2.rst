============================
OAuth 2: Creating a Provider
============================

Note that OAuth 2 provider is still very much a work in progress, consider it a
preview of a near future =)

**1. Which framework are you using?**

    OAuthLib is a dependency free library that may be used with any web
    framework. That said, there are framework specific helper decorator classes
    to make your life easier. The one we will be using in this example is for
    Django. For others, and information on how to create one, check out
    :doc:`decorators`.

    The main purpose of these decoraters is to help marshall between the
    framework specific request object and framework agnostic url, headers, body
    and http method parameters. They may also be useful for making sure common
    best security practices are followed.

    Their purpose is not to be a full solution to all your needs as a provider,
    for that you will want to seek out framework specific extensions building
    upon OAuthLib. See the section on :doc:`decorators` for a list of
    extensions.

    Relevant sections include:

    .. toctree::
        :maxdepth: 1

        decorators

**2. Create your datastore models**

    These models will represent various OAuth specific concepts. There are a few
    important links between them that the security of OAuth is based on. Below
    is a suggestion for models and why you need certain properties. There is
    also example Django model fields which should be straightforward to
    translate to other ORMs such as SQLAlchemy and the Appengine Datastore.

    **User (or Resource Owner)**
        The user of your site which resources might be access by clients upon
        authorization from the user. In our example we will re-use the User
        model provided in django.contrib.auth.models. How the user authenticates
        is orthogonal from OAuth and may be any way you prefer::

            from django.contrib.auth.models import User

    **Client (or Consumer)**
        The client interested in accessing protected resources.

        **Client Identifier**:
            Required. The identifier the client will use during the OAuth
            workflow. Structure is up to you and may be a simple UUID::

                client_id = django.db.models.CharField(max_length=100, unique=True)

        **User**:
            Recommended. It is common practice to link each client with one of
            your existing users. Whether you do associate clients and users or
            not, ensure you are able to protect yourself against malicious
            clients::

                user = django.db.models.ForeignKey(User)

        **Grant Type**:
            Required. The grant type the client may utilize. This should only be
            one per client as each grant type has different security properties
            and it is best to keep them separate to avoid mistakes::

                # max_length and choices depend on which grants you support
                grant_type = django.db.models.CharField(max_length=18,
                    choices=[('authorization_code', 'Authorization code')])

        **Response Type**:
            Required, if using a grant type with an associated response type
            (eg. Authorization Code Grant) or using a grant which only utilizes
            response types (eg. Implicit Grant)::

                # max_length and choices depend on which response types you support
                response_type = django.db.models.CharField(max_length=4,
                    choices=[('code', 'Authorization code')])

        **Scopes**:
            Required. The list of scopes the client may request access to. If
            you allow multiple types of grants this will vary related to their
            different security properties. For example, the Implicit Grant might
            only allow read-only scopes but the Authorization Grant also allow
            writes::

                # You could represent it either as a list of keys or by serializing
                # the scopes into a string.
                scopes = django.db.models.TextField()

                # You might also want to mark a certain set of scopes as default
                # scopes in case the client does not specify any in the authorization
                default_scopes = django.db.models.TextField()

        **Redirect URIs**:
            These are the absolute URIs that a client may use to redirect to after
            authorization. You should never allow a client to redirect to a URI
            that has not previously been registered::

                # You could represent the URIs either as a list of keys or by
                # serializing them into a string.
                redirect_uris = django.db.models.TextField()

                # You might also want to mark a certain URI as default in case the
                # client does not specify any in the authorization
                default_redirect_uri = django.db.models.TextField()

    **Bearer Token (OAuth 2 Standard Token)**
        The most common type of OAuth 2 token. Through the documentation this
        will be considered an object with several properties, such as token type
        and expiration date, and distinct from the access token it contains.
        Think of OAuth 2 tokens as containers and access tokens and refresh
        tokens as text.

        **Client**:
            Association with the client to whom the token was given::

                client = django.db.models.ForeignKey(Client)

        **User**:
            Association with the user to which protected resources this token
            grants access::

                user = django.db.models.ForeignKey(User)

        **Scopes**:
            Scopes to which the token is bound. Attempt to access protected
            resources outside these scopes will be denied::

                # You could represent it either as a list of keys or by serializing
                # the scopes into a string.
                scopes = django.db.models.TextField()

        **Access Token**:
            An unguessable unique string of characters::

                access_token = django.db.models.CharField(max_length=100, unique=True)

        **Refresh Token**:
            An unguessable unique string of characters. This token is only
            supplied to confidential clients. For example the Authorization Code
            Grant or the Resource Owner Password Credentials Grant::

                refresh_token = django.db.models.CharField(max_length=100, unique=True)

        **Expiration time**:
            Exact time of expiration. Commonly this is one hour after creation::

                expires_at = django.db.models.DateTimeField()

    **Authorization Code**
        This is specific to the Authorization Code grant and represent the
        temporary credential granted to the client upon successful
        authorization. It will later be exchanged for an access token, when that
        is done it should cease to exist. It should have a limited life time,
        less than ten minutes. This model is similar to the Bearer Token as it
        mainly acts a temporary storage of properties to later be transferred to
        the token.

        **Client**:
            Association with the client to whom the token was given::

                client = django.db.models.ForeignKey(Client)

        **User**:
            Association with the user to which protected resources this token
            grants access::

                user = django.db.models.ForeignKey(User)

        **Scopes**:
            Scopes to which the token is bound. Attempt to access protected
            resources outside these scopes will be denied::

                # You could represent it either as a list of keys or by serializing
                # the scopes into a string.
                scopes = django.db.models.TextField()

        **Authorization Code**:
            An unguessable unique string of characters::

                code = django.db.models.CharField(max_length=100, unique=True)

        **Expiration time**:
            Exact time of expiration. Commonly this is under ten minutes after
            creation::

                expires_at = django.db.models.DateTimeField()

**3. Implement a validator**

    The majority of the work involved in implementing an OAuth 2 provider
    relates to mapping various validation and persistence methods to a storage
    backend. The not very accurately named interface you will need to implement
    is called a :doc:`RequestValidator <validator>` (name suggestions welcome).

    An example of a very basic implementation of the validate_client_id method
    can be seen below::

        from oauthlib.oauth2 import RequestValidator

        # From the previous section on models
        from my_models import Client

        class MyRequestValidator(RequestValidator):

            def validate_client_id(self, client_id, request):
                try:
                    Client.objects.get(client_id=client_id)
                    return True
                except Client.DoesNotExist:
                    return False

    The full API you will need to implement is available in the
    :doc:`RequestValidator <validator>` section. You might not need to implement
    all methods depending on which grant types you wish to support. A skeleton
    validator listing the methods required for the WebApplicationServer is
    available in the `examples`_ folder on GitHub.

    ..  _`examples`: https://github.com/idan/oauthlib/blob/master/examples/skeleton_oauth2_web_application_server.py

    Relevant sections include:

    .. toctree::
        :maxdepth: 1

        validator
        security


**4. Create your composite endpoint**

    Each of the endpoints can function independently from each other, however
    for this example it is easier to consider them as one unit. An example of a
    pre-configured all-in-one Authorization Code Grant endpoint is given below::

        # From the previous section on validators
        from my_validator import MyRequestValidator

        from oauthlib.oauth2 import WebApplicationServer
        from oauthlib.oauth2.ext.django import OAuth2ProviderDecorator

        validator = MyRequestValidator()
        server = WebApplicationServer(validator)
        provider = OAuth2ProviderDecorator('/error', server)    # See next section

    Relevant sections include:

    .. toctree::
        :maxdepth: 1

        preconfigured_servers


**5. Decorate your endpoint views**

    We are implementing support for the Authorization Code Grant and will
    therefore need two views for the authorization, pre- and post-authorization
    together with the token view. We also include an error page to redirect
    users to if the client supplied invalid credentials in their redirection,
    for example an invalid redirect URI::

        @login_required
        @provider.pre_authorization_view
        def authorize(request, client_id=None, scopes=None, state=None,
            redirect_uri=None, response_type=None):
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
            # appended to the request object passed into the validator methods.
            # In almost every case, you will want to include the current
            # user in these extra credentials in order to associate the user with
            # the authorization code or bearer token.
            return request.POST.getlist['scopes'], {'user': request.user}


        @provider.access_token_view
        def token_response(request):
            # Not much too do here for you, return a dict with extra credentials
            # you want appended to request.credentials passed to the save_bearer_token
            # method of the validator.
            return {'extra': 'creds'}

        def error(request):
            # The /error page users will be redirected to if there was something
            # wrong with the credentials the client included when redirecting the
            # user to the authorization form. Mainly if the client was invalid or
            # included a malformed / invalid redirect url.
            # Error and description can be found in
            # GET['error'] and GET['error_description']
            return HttpResponse('Bad client! Warn user!')


**6. Protect your APIs using scopes**

    At this point you are ready to protect your API views with OAuth. Take some
    time to come up with a good set of scopes as they can be very powerful in
    controlling access::

        @provider.protected_resource_view(scopes=['images'])
        def i_am_protected(request, client, resource_owner, **kwargs):
            # One of your many OAuth 2 protected resource views
            # Returns whatever you fancy
            # May be bound to various scopes of your choosing
            return HttpResponse('pictures of cats')

**7. Let us know how it went!**

    Drop a line in our `G+ community`_ or open a `GitHub issue`_ =)

    .. _`G+ community`: https://plus.google.com/communities/101889017375384052571
    .. _`GitHub issue`: https://github.com/idan/oauthlib/issues/new

    If you run into issues it can be helpful to enable debug logging::

        import logging
        log = logging.getLogger('oauthlib')
        log.addHandler(logging.StreamHandler(sys.stdout))
        log.setLevel(logging.DEBUG)
