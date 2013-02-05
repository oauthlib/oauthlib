Creating an OAuth provider
==========================

Note that the current OAuth1 provider interface will change into one resembling the work in progress OAuth 2 provider in a not too distant future. More information in `issue #95`_.

.. _`issue #95`: https://github.com/idan/oauthlib/issues/95

Implementing an OAuth provider is simple with OAuthLib. It is done by inheriting from ``oauthlib.oauth1.rfc5849.Server`` and overloading a few key methods. The base class provide a secure by default implementation including a ``verify_request`` method as well as several input validation methods, all configurable using properties. While it is straightforward to use OAuthLib directly with your web framework of choice it is worth first exploring whether there is an OAuthLib based OAuth provider plugin available for your framework.

A few important facts regarding OAuth security
----------------------------------------------

* **OAuth without SSL is a Bad Idea™** and it's strongly recommended to use SSL for all interactions both with your API as well as for setting up tokens. An example of when it's especially bad is when sending POST requests with form data, this data is not accounted for in the OAuth signature and a successfull man-in-the-middle attacker could swap your form data (or files) to whatever he pleases without invalidating the signature. This is an even bigger issue if you fail to check nonce/timestamp pairs for each request, allowing an attacker who intercept your request to replay it later, overriding your initial request. **Server defaults to fail all requests which are not made over HTTPS**, you can explicitely disable this using the enforce_ssl property.

* **Tokens must be random**, OAuthLib provides a method for generating secure tokens and it's packed into ``Server.generate_token``, use it. If you decide to roll your own, use ``random.SystemRandom`` which is based on ``os.urandom`` rather than the default ``random`` based on the effecient but not truly random Mersenne Twister. Predicatble tokens allow attackers to bypass virtually all defences OAuth provides.

* **Timing attacks are real** and more than possible if you host your application inside a shared datacenter. Ensure all ``validate_`` methods execute in near constant time no matter which input is given. This will be covered in more detail later. Failing to account for timing attacks could **enable attackers to enumerate tokens and successfully guess HMAC secrets**. Note that RSA keys are protected through RSA blinding and are not at risk.

* **Nonce and timestamps must be checked**, do not ignore this as it's a simple and effective way to prevent replay attacks. Failing this allows online bruteforcing of secrets which is not something you want.

* **Whitelisting is your friend** and effectively eliminates SQL injection and other nasty attacks on your precious data. More details on this in the ``check_`` methods. 

* **Require all callback URIs to be registered before use**. OAuth providers are in the unique position of being able to restrict which URIs may be submitted, making validation simple and safe. This registration should be done in your Application management interface. 

Methods that must be overloaded
-------------------------------

Example implementations have been provided, note that the database used is a simple dictionary and serves only an illustrative purpose. Use whichever database suits your project and how to access it is entirely up to you. The methods are introduced in an order which should make understanding their use more straightforward and as such it could be worth reading what follows in chronological order.

#. ``validate_timestamp_and_nonce(self, client_key, timestamp, nonce, request_token=None, access_token=None)``
#. ``validate_client_key(self, client_key)``
#. ``validate_request_token(self, client_key, request_token)``
#. ``validate_access_token(self, client_key, access_token)``
#. ``dummy_client(self)``
#. ``dummy_request_token(self)``
#. ``dummy_access_token(self)``
#. ``validate_redirect_uri(self, client_key, redirect_uri)``
#. ``validate_requested_realm(self, client_key, realm)``
#. ``validate_realm(self, client_key, access_token, uri, required_realm=None)``
#. ``validate_verifier(self, client_key, request_token, verifier)``
#. ``get_client_secret(self, client_key)``
#. ``get_request_token_secret(self, client_key, request_token)``
#. ``get_access_token(self, client_key, access_token)``
#. ``get_rsa_key(self, client_key)``

``validate_timestamp_and_nonce(self, client_key, timestamp, nonce, request_token=None, access_token=None)``

The first thing you want to do is check nonce and timestamp, which are associated with a client key and possibly a token, and immediately fail the request if the nonce/timestamp pair has been used before. This prevents replay attacks and is an essential part of OAuth security. Note that this is done before checking the validity of the client and token.::

       nonces_and_timestamps_database = [
          (u'foo', 1234567890, u'rannoMstrInghere', u'bar') 
       ]

       def validate_timestamp_and_nonce(self, client_key, timestamp, nonce, 
          request_token=None, access_token=None):

          return ((client_key, timestamp, nonce, request_token or access_token)
                   in self.nonces_and_timestamps_database)

``validate_client_key(self, client_key)`` and 
``validate_request_token(self, client_key, request_token)``
``validate_access_token(self, client_key, access_token)``

Validation of client keys simply ensure that the provided key is associated with a registered client. Same goes for the tokens::

        clients_database = [u'foo']

        def validate_client_key(self, client_key):
           return client_key in self.clients_database

        request_token_database = [(u'foo', u'bar')]
        access_token_database = []

        def validate_request_token(self, client_key, request_token):
           return (client_key, request_token) in self.request_token_database

Note that your dummy client and dummy tokens must validate to false and do so without affecting the execution time of the client validation. **Avoid doing this**::

        def validate_client_key(self, client_key):
           if client_key == dummy_client:
               return False
           return client_key in self.clients_database


``dummy_client(self)``, ``dummy_request_token(self)`` and ``dummy_access_token(self)``

Dummy values are used to enable the verification to execute in near constant time even if the client key or token is invalid. No early exits are taken during the verification and even a signature is calculated for the dummy client and/or token. The use of these dummy values effectively eliminate the chance of an attacker guessing tokens and secrets by measuring the response time of request verification::

        @property
        def dummy_client(self):
           return u'dummy_client'

        @property
        def dummy_resource_owner(self):
           return u'dummy_resource_owner'

``validate_redirect_uri(self, client_key, redirect_uri)``

All redirection URIs (provided when obtaining request tokens) must be validated. If you require clients to register these URIs this is a trivial operation. It is worth considering a hash comparison of values since URIs could be hard to sanitize and thus not optimal to throw into a database query. The example below illustrates this using pythons builtin membership comparison::

       def validate_redirect_uri(self, client_key, redirect_uri):
           redirect_uris = db.get_all_redirect_uris_for_client(client_key)
           return redirect_uri in redirect_uris

As opposed to::

       def validate_redirect_uri(self, client_key, redirect_uri):
          return len(db.query_client_redirect_uris(uri=redirect_uri).result) == 1

Using our familiar example dict database::

        redirect_uris = {
            u'foo' :  [u'https://some.fance.io/callback']
        }
 
        def validate_redirect_uri(self, client_key, redirect_uri):
           return (client_key in self.redirect_uris and 
                   redirect_uri in self.redirect_uris.get(client_key))

``validate_realm(self, client_key, resource_owner_key, realm, uri)``

Realms are useful when restricting scope. Scope could be a variety of things but commonly relates to privileges (read/write) or content categories (photos/private/code). Since realms are commonly associated not only with client keys and tokens but also a resource URI the requested URI is an included argument as well::

         assigned_realms = {
              u'foo' : [u'photos']
         }

         realms = {
            (u'foo', u'bar') : u'photos'
         }

         def validate_requested_realm(self, client_key, realm):
            return realm in self.assigned_realms.get(client_key)

         def validate_realm(self, client_key, access_token, uri=None, required_realm=None):
            if required_realm:
                return self.realms.get((client_key, access_token)) in required_realm
            else:
                # Use the URI to figure out if the associated realm is valid
             
``validate_verifier(self, client_key, resource_owner_key, verifier)``

Verifiers are assigned to a client after the resource owner (user) has authorized access. They will thus only be present (and valid) in access token request. Naturally they must be validated and it should be done in near constant time (to avoid verifier enumeration). To achieve this we need a constant time string comparison which is provided by OAuthLib in ``oauthlib.common.safe_string_equals``::

       verifiers = {
          (u'foo', u'request_token') : u'randomVerifierString'
       }

       def validate_verifier(self, client_key, request_token, verifier):
           return safe_string_equals(verifier, self.verifiers.get((client_key, request_token))

``get_client_secret(self, client_key)``

Fetches the client secret associated with client key from your database. Note that your database should include a dummy key associated with your dummy user mentioned previously::

        client_secrets_database = {
           u'foo' : u'fooshizzle',
           u'user1' : u'password1',
           u'dummy_client' : u'dummy-secret'
        }

        def get_client_secret(self, client_key):
           return self.client_secrets_database.get(client_key)

``get_request_token_secret(self, client_key, request_token)``
``get_access_token_secret(self, client_key, access_token)``

Fetches the resource owner secret associated with client key and token. Similar to ``get_client_secret`` the database should include a dummy resource owner secret::

       request_token_secrets_database = {
          (u'foo', u'someResourceOwner') : u'seeeecret',
          (u'dummy_client', 'dummy_resource_owner') : u'dummy-owner-secret'
       }
       
       def get_request_token_secret(client_key, request_token):
          return self.request_token_secrets.get((client_key, request_token))

``get_rsa_key(self, client_key)``

 If RSA signatures are used the Server must fetch the **public key** associated with the client. There should be a dummy RSA public key associated with dummy clients. Keys have been cut in length for obvious reasons::

      rsa_public_keys = {
         u'foo' : u'-----BEGIN PUBLIC KEY-----MIGfMA0GCSqG....',
         u'dummy_client' : u'-----BEGIN PUBLIC KEY-----e1Sb3fKQIDAQA....'
      }

      def get_rsa_key(self, client_key):
         return self.rsa_public_keys.get(client_key)
                            
Verifying requests
------------------

Request verification is provided through the ``Server.verify_request`` method which has the following signature::

     verify_request(self, uri, http_method=u'GET', body=None, headers=None, 
                    require_resource_owner=True, 
                    require_verifier=False, 
                    require_realm=False,
                    required_realm=None)

There are three types of verifications you will want to perform, all which could be altered through the use of a realm parameter if you choose to allow/require this. Note that if verify_request returns false a HTTP 401Unauthorized should be returned. If a ValueError is raised a HTTP 400 Bad Request response should be returned. All request verifications will look similar to the following::

   try:
      authorized = server.verify_request(uri, http_method, body, headers)
      if not authorized:
         # return a HTTP 401 Unauthorized response
      else:
         # Create, save and return request token/access token/protected resource 
         # or whatever you had in mind that required OAuth 
   except ValueError:
       # return a HTTP 400 Bad Request response    

The only change will be parameters to the verify_request method.

#. Requests to obtain request tokens, these may include an optional redirection URI parameter::

    authorized = server.verify_request(uri, http_method, body, headers, require_resource_owner=False)

#. Requests to obtain access tokens, these should always include a verifier and a resource owner key::

    authorized = server.verify_request(uri, http_method, body, headers, require_verifier=True)

#. Requests to protected resources::

    authorized = server.verify_request(uri, http_method, body, headers)


Configuring check methods and their respective properties
---------------------------------------------------------

There are a number of input validation checks that perform white listing of input parameters. I hope to document them soon but for now please refer to the Server source code found in oauthlib.oauth1.rfc5849.__init__.py. 
