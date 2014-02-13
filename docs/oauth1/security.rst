A few important facts regarding OAuth security
==============================================

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
        HTTPS**, you can explicitly disable this using the enforce_ssl
        property.

    * **Tokens must be random**, OAuthLib provides a method for generating
        secure tokens and it's packed into ``oauthlib.common.generate_token``,
        use it. If you decide to roll your own, use ``random.SystemRandom``
        which is based on ``os.urandom`` rather than the default ``random``
        based on the effecient but not truly random Mersenne Twister.
        Predictable tokens allow attackers to bypass virtually all defences
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
