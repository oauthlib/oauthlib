OAuth 1: Creating a Provider
============================

Note that the current OAuth1 provider interface will change into one resembling
the work in progress OAuth 2 provider in a not too distant future. More
information in `issue #95`_.

.. _`issue #95`: https://github.com/idan/oauthlib/issues/95

Implementing an OAuth provider is simple with OAuthLib. It is done by inheriting
from ``oauthlib.oauth1.rfc5849.Server`` and overloading a few key methods. The
base class provide a secure by default implementation including a
``verify_request`` method as well as several input validation methods, all
configurable using properties. While it is straightforward to use OAuthLib
directly with your web framework of choice it is worth first exploring whether
there is an OAuthLib based OAuth provider plugin available for your framework.

**A few important facts regarding OAuth security**

    * **OAuth without SSL is a Bad Idea™** and it's strongly recommended to use
        SSL for all interactions both with your API as well as for setting up
        tokens. An example of when it's especially bad is when sending POST
        requests with form data, this data is not accounted for in the OAuth
        signature and a successfull man-in-the-middle attacker could swap your
        form data (or files) to whatever he pleases without invalidating the
        signature. This is an even bigger issue if you fail to check
        nonce/timestamp pairs for each request, allowing an attacker who
        intercept your request to replay it later, overriding your initial
        request. **Server defaults to fail all requests which are not made over
        HTTPS**, you can explicitely disable this using the enforce_ssl
        property.

    * **Tokens must be random**, OAuthLib provides a method for generating
        secure tokens and it's packed into ``oauthlib.common.generate_token``,
        use it. If you decide to roll your own, use ``random.SystemRandom``
        which is based on ``os.urandom`` rather than the default ``random``
        based on the effecient but not truly random Mersenne Twister.
        Predicatble tokens allow attackers to bypass virtually all defences
        OAuth provides.

    * **Timing attacks are real** and more than possible if you host your
        application inside a shared datacenter. Ensure all ``validate_`` methods
        execute in near constant time no matter which input is given. This will
        be covered in more detail later. Failing to account for timing attacks
        could **enable attackers to enumerate tokens and successfully guess HMAC
        secrets**. Note that RSA keys are protected through RSA blinding and are
        not at risk.

    * **Nonce and timestamps must be checked**, do not ignore this as it's a
        simple and effective way to prevent replay attacks. Failing this allows
        online bruteforcing of secrets which is not something you want.

    * **Whitelisting is your friend** and effectively eliminates SQL injection
        and other nasty attacks on your precious data. More details on this in
        the ``check_`` methods.

    * **Require all callback URIs to be registered before use**. OAuth providers
        are in the unique position of being able to restrict which URIs may be
        submitted, making validation simple and safe. This registration should
        be done in your Application management interface.

**Verifying requests**

    Request verification is provided through the ``Server.verify_request``
    method which has the following signature::

         verify_request(self, uri, http_method=u'GET', body=None, headers=None,
                        require_resource_owner=True,
                        require_verifier=False,
                        require_realm=False,
                        required_realm=None)

    There are three types of verifications you will want to perform, all which
    could be altered through the use of a realm parameter if you choose to
    allow/require this. Note that if verify_request returns false a HTTP
    401Unauthorized should be returned. If a ValueError is raised a HTTP 400 Bad
    Request response should be returned. All request verifications will look
    similar to the following::

        try:
            authorized = server.verify_request(uri, http_method, body, headers)
            if not authorized:
                # return a HTTP 401 Unauthorized response
                pass
            else:
               # Create, save and return request token/access token/protected resource
               # or whatever you had in mind that required OAuth
               pass
        except ValueError:
            # return a HTTP 400 Bad Request response
            pass

    The only change will be parameters to the verify_request method.

    #. Requests to obtain request tokens, these may include an optional
       redirection URI parameter::

        authorized = server.verify_request(uri, http_method, body, headers,
                                           require_resource_owner=False)

    #. Requests to obtain access tokens, these should always include a verifier
       and a resource owner key::

        authorized = server.verify_request(uri, http_method, body, headers,
                                           require_verifier=True)

    #. Requests to protected resources::

        authorized = server.verify_request(uri, http_method, body, headers)


**Configuring check methods and their respective properties**

    There are a number of input validation checks that perform white listing of
    input parameters. I hope to document them soon but for now please refer to
    the Server source code found in oauthlib.oauth1.rfc5849.__init__.py.

**Methods that must be overloaded**

.. autoclass:: oauthlib.oauth1.rfc5849.Server
    :members:

