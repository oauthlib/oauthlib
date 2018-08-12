===================
Creating a Provider
===================

OAuthLib is a framework independent library that may be used with any web
framework. That said, there are framework specific helper libraries
to make your life easier.

- For Flask there is `flask-oauthlib`_.

If there is no support for your favourite framework and you are interested
in providing it then you have come to the right place. OAuthLib can handle
the OAuth logic and leave you to support a few framework and setup specific
tasks such as marshalling request objects into URI, headers and body arguments
as well as provide an interface for a backend to store tokens, clients, etc.

.. _`flask-oauthlib`: https://github.com/lepture/flask-oauthlib

.. contents:: Tutorial Contents
    :depth: 3


1. Create your datastore models
-------------------------------

These models will represent various OAuth specific concepts. There are a few
important links between them that the security of OAuth is based on. Below
is a suggestion for models and why you need certain properties. There is
also example SQLAlchemy model fields which should be straightforward to
translate to other ORMs such as Django and the Appengine Datastore.

1.1 User (or Resource Owner)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The user of your site which resources might be access by clients upon
authorization from the user. Below is a crude example of a User model, yours
is likely to differ and the structure is not important. Neither is how the user
authenticates, as long as it does before authorizing::

    Base = sqlalchemy.ext.declarative.declarative_base()
    class ResourceOwner(Base):
        __tablename__ = "users"

        id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
        name = sqlalchemy.Column(sqlalchemy.String)
        email = sqlalchemy.Column(sqlalchemy.String)
        password = sqlalchemy.Column(sqlalchemy.String)

1.2 Client (or Consumer)
^^^^^^^^^^^^^^^^^^^^^^^^

The client interested in accessing protected resources.

**Client Identifier / Consumer key**:
    Required. The identifier the client will use during the OAuth
    workflow. Structure is up to you and may be a simple UID::

        client_key = sqlalchemy.Column(sqlalchemy.String)

**Client secret**:
    Required for HMAC-SHA1 and PLAINTEXT. The secret the client will use when
    verifying requests during the OAuth workflow. Has to be accesible as
    plaintext (i.e. not hashed) since it is used to recreate and validate
    request signatured::

        client_secret = sqlalchemy.Column(sqlalchemy.String)

**Client public key**:
    Required for RSA-SHA1. The public key used to verify the signature of
    requests signed by the clients private key::

        rsa_key = sqlalchemy.Column(sqlalchemy.String)

**User**:
    Recommended. It is common practice to link each client with one of
    your existing users. Whether you do associate clients and users or
    not, ensure you are able to protect yourself against malicious
    clients::

        user = Column(Integer, ForeignKey("users.id"))

**Realms**:
    Required. The list of realms the client may request access to. While realm
    use is largely undocumented in the spec you may think of them as very
    similar to OAuth 2 scopes.::

        # You could represent it either as a list of keys or by serializing
        # the scopes into a string.
        realms = sqlalchemy.Column(sqlalchemy.String)

        # You might also want to mark a certain set of scopes as default
        # scopes in case the client does not specify any in the authorization
        default_realms = sqlalchemy.Column(sqlalchemy.String)

**Redirect URIs**:
    These are the absolute URIs that a client may use to redirect to after
    authorization. You should never allow a client to redirect to a URI
    that has not previously been registered::

        # You could represent the URIs either as a list of keys or by
        # serializing them into a string.
        redirect_uris = sqlalchemy.Column(sqlalchemy.String)

        # You might also want to mark a certain URI as default in case the
        # client does not specify any in the authorization
        default_redirect_uri = sqlalchemy.Column(sqlalchemy.String)

1.3 Request Token + Verifier
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In OAuth 1 workflow the first step is obtaining/providing a request token. This
token captures information about the client, its callback uri and realms
requested. This step is not present in OAuth2 as these credentials are supplied
directly in the authorization step.

When the request token is first created the user is unknown. The user is
associated with a request token during the authorization step. After successful
authorization the client is presented with a verifier code (should be linked to
request token) as a proof of authorization. This verifier code is later used to
obtain an access token.

**Client**:
    Association with the client to whom the request token was given::

        client = Column(Integer, ForeignKey("clients.id"))

**User**:
    Association with the user to which protected resources this token
    requests access::

        user = Column(Integer, ForeignKey("users.id"))

**Realms**:
    Realms to which the token is bound. Attempt to access protected
    resources outside these realms will be denied::

        # You could represent it either as a list of keys or by serializing
        # the scopes into a string.
        realms = sqlalchemy.Column(sqlalchemy.String)

**Redirect URI**:
    The callback URI used to redirect back to the client after user
    authorization is completed::

        redirect_uri = sqlalchemy.Column(sqlalchemy.String)

**Request Token**:
    An unguessable unique string of characters::

        request_token = sqlalchemy.Column(sqlalchemy.String)

**Request Token Secret**:
    An unguessable unique string of characters. This is a temporary secret used
    by the HMAC-SHA1 and PLAINTEXT signature methods when obtaining an
    access token later::

        request_token_secret = sqlalchemy.Column(sqlalchemy.String)

**Authorization Verifier**:
    An unguessable unique string of characters. This code asserts that the user
    has given the client authorization to access the requested realms. It is
    initially nil when the client obtains the request token in the first step, and
    set after user authorization is given in the second step::

        verifier = sqlalchemy.Column(sqlalchemy.String)

1.4 Access Token
^^^^^^^^^^^^^^^^

Access tokens are provided to clients able to present a valid request token
together with its associated verifier. It will allow the client to access 
protected resources and is normally not associated with an expiration. Although
you should consider expiring them as it increases security dramatically.

The user and realms will need to be transferred from the request token to the
access token. It is possible that the list of authorized realms is smaller
than the list of requested realms. Clients can observe whether this is the case
by comparing the `oauth_realms` parameter given in the token reponse. This way
of indicating change of realms is backported from OAuth2 scope behaviour and is
not in the OAuth 1 spec.

**Client**:
    Association with the client to whom the access token was given::

        client = Column(Integer, ForeignKey("clients.id"))

**User**:
    Association with the user to which protected resources this token
    grants access::

        user = Column(Integer, ForeignKey("users.id"))

**Realms**:
    Realms to which the token is bound. Attempt to access protected
    resources outside these realms will be denied::

        # You could represent it either as a list of keys or by serializing
        # the scopes into a string.
        realms = sqlalchemy.Column(sqlalchemy.String)

**Access Token**:
    An unguessable unique string of characters::

        access_token = sqlalchemy.Column(sqlalchemy.String)

**Access Token Secret**:
    An unguessable unique string of characters. This secret is used
    by the HMAC-SHA1 and PLAINTEXT signature methods when accessing protected
    resources::

        access_token_secret = sqlalchemy.Column(sqlalchemy.String)

2. Implement a validator
------------------------

The majority of the work involved in implementing an OAuth 1 provider
relates to mapping various validation and persistence methods to a storage
backend. The not very accurately named interface you will need to implement
is called a :doc:`RequestValidator <validator>` (name suggestions welcome).

An example of a very basic implementation of the ``validate_client_key`` method
can be seen below::

    from oauthlib.oauth1 import RequestValidator

    # From the previous section on models
    from my_models import Client

    class MyRequestValidator(RequestValidator):

        def validate_client_key(self, client_key, request):
            try:
                Client.query.filter_by(client_key=client_key).one()
                return True
            except NoResultFound:
                return False

The full API you will need to implement is available in the
:doc:`RequestValidator <validator>` section. You might not need to implement
all methods depending on which signature methods you wish to support.

Relevant sections include:

.. toctree::
    :maxdepth: 1

    validator
    security


3. Create your composite endpoint
---------------------------------

Each of the endpoints can function independently from each other, however
for this example it is easier to consider them as one unit. An example of a
pre-configured all-in-one OAuth 1 RFC compliant [#compliant]_ endpoint is
given below::

    # From the previous section on validators
    from my_validator import MyRequestValidator

    from oauthlib.oauth1 import WebApplicationServer

    validator = MyRequestValidator()
    server = WebApplicationServer(validator)


Relevant sections include:

.. toctree::
    :maxdepth: 1

    preconfigured_servers

.. [#compliant] Standard 3-legged OAuth 1 as defined in the RFC specification.


4. Create your endpoint views
-----------------------------

Standard 3 legged OAuth requires 4 views, request and access token together with
pre- and post-authorization. In addition an error view should be defined
where users can be informed of invalid/malicious authorization requests.

The example uses Flask but should be transferable to any framework.

.. code-block:: python

    from flask import Flask, redirect, Response, request, url_for
    from oauthlib.oauth1 import OAuth1Error
    import urlparse


    app = Flask(__name__)


    @app.route('/request_token', methods=['POST'])
    def request_token():
        h, b, s = provider.create_request_token_response(request.url,
                http_method=request.method,
                body=request.data,
                headers=request.headers)
        return Response(b, status=s, headers=h)


    @app.route('/authorize', methods=['GET'])
    def pre_authorize():
        realms, credentials = provider.get_realms_and_credentials(request.url,
                http_method=request.method,
                body=request.data,
                headers=request.headers)
        client_key = credentials.get('resource_owner_key', 'unknown')
        response = '<h1> Authorize access to %s </h1>' % client_key
        response += '<form method="POST" action="/authorize">'
        for realm in realms or []:
            response += ('<input type="checkbox" name="realms" ' +
                            'value="%s"/> %s' % (realm, realm))
        response += '<input type="submit" value="Authorize"/>'
        return response


    @app.route('/authorize', methods=['POST'])
    def post_authorize():
        realms = request.form.getlist('realms')
        try:
            h, b, s = provider.create_authorization_response(request.url,
                    http_method=request.method,
                    body=request.data,
                    headers=request.headers,
                    realms=realms)
            if s == 200:
                return 'Your verifier is: ' + str(urlparse.parse_qs(b)['oauth_verifier'][0])
            else:
                return Response(b, status=s, headers=h)
        except OAuth1Error as e:
            return redirect(e.in_uri(url_for('/error')))


    @app.route('/access_token', methods=['POST'])
    def access_token():
        h, b, s = provider.create_access_token_response(request.url,
                http_method=request.method,
                body=request.data,
                headers=request.headers)
        return Response(b, status=s, headers=h)


    @app.route('/error', methods=['GET'])
    def error():
        # Invalid request token will be most likely
        # Could also be an attempt to change the authorization form to try and
        # authorize realms outside the allowed for this client.
        return 'client did something bad'

5. Protect your APIs using realms
---------------------------------

Let's define a decorator we can use to protect the views.

.. code-block:: python


    def oauth_protected(realms=None):
        def wrapper(f):
            @functools.wraps(f)
            def verify_oauth(*args, **kwargs):
                validator = OAuthValidator()  # your validator class
                provider = ResourceEndpoint(validator)
                v, r = provider.validate_protected_resource_request(request.url,
                        http_method=request.method,
                        body=request.data,
                        headers=request.headers,
                        realms=realms or [])
                if v:
                    return f(*args, **kwargs)
                else:
                    return abort(403)
            return verify_oauth
        return wrapper

At this point you are ready to protect your API views with OAuth. Take some
time to come up with a good set of realms as they can be very powerful in
controlling access.

.. code-block:: python

    @app.route('/secret', methods=['GET'])
    @oauth_protected(realms=['secret'])
    def protected_resource():
        return 'highly confidential'

6. Try your provider with a quick CLI client
--------------------------------------------

This example assumes you use the client key `key` and client secret `secret`
shown below as well as run your flask server locally on port `5000`.

.. code-block:: bash

    $ pip install requests requests-oauthlib

.. code-block:: python

    >>> key = 'abcdefghijklmnopqrstuvxyzabcde'
    >>> secret = 'foo'

    >>> # OAuth endpoints given in the Bitbucket API documentation
    >>> request_token_url = 'http://127.0.0.1:5000/request_token'
    >>> authorization_base_url = 'http://127.0.0.1:5000/authorize'
    >>> access_token_url = 'http://127.0.0.1:5000/access_token'

    >>> # 2. Fetch a request token
    >>> from requests_oauthlib import OAuth1Session
    >>> oauth = OAuth1Session(key, client_secret=secret,
    >>>         callback_uri='http://127.0.0.1/cb')
    >>> oauth.fetch_request_token(request_token_url)

    >>> # 3. Redirect user to your provider implementation for authorization
    >>> authorization_url = oauth.authorization_url(authorization_base_url)
    >>> print 'Please go here and authorize,', authorization_url

    >>> # 4. Get the authorization verifier code from the callback url
    >>> redirect_response = raw_input('Paste the full redirect URL here:')
    >>> oauth.parse_authorization_response(redirect_response)

    >>> # 5. Fetch the access token
    >>> oauth.fetch_access_token(access_token_url)

    >>> # 6. Fetch a protected resource, i.e. user profile
    >>> r = oauth.get('http://127.0.0.1:5000/secret')
    >>> print r.content

7. Let us know how it went!
---------------------------

Drop a line in our `Gitter OAuthLib community`_ or open a `GitHub issue`_ =)

.. _`Gitter OAuthLib community`: https://gitter.im/oauthlib/Lobby
.. _`GitHub issue`: https://github.com/oauthlib/oauthlib/issues/new

If you run into issues it can be helpful to enable debug logging::

    import logging
    import sys
    log = logging.getLogger('oauthlib')
    log.addHandler(logging.StreamHandler(sys.stdout))
    log.setLevel(logging.DEBUG)
