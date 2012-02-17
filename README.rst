OAuthLib: a generic library for signing OAuth requests
======================================================

OAuth often seems complicated and difficult-to-implement. There are several
prominent libraries for signing OAuth requests, but they all suffer from one of the following:

1. They predate the `OAuth 1.0 spec`_, AKA RFC 5849.
2. They assume the usage of a specific HTTP request library.
3. They only support use of HMAC-SHA1 signatures and authorization headers.

.. _`OAuth 1.0 spec`: http://tools.ietf.org/html/rfc5849

OAuthLib is a generic utility which implements the logic of OAuth without
assuming a specific HTTP request object or workflow. Use it to graft OAuth support 
onto your favorite HTTP library. If you're a maintainer of such a library, 
write a thin veneer on top of OAuthLib and get OAuth support for very little effort.

OAuthLib features
-----------------

* Easy to use OAuth class for any server and workflow.
* Convenience methods for OAuth clients including signing, encoding and nonces.
* Conveniene methods for OAuth servers including verification and token generation.
* Completely decoupled from HTTP libraries.
* Supports all signature methods; HMAC-SHA1, RSA-SHA1 and PLAINTEXT.
* Supports all methods of supplying credentials; Authorization header, Request URI Query and Form Encoded Body.

OAuthLib takes care of all encoding, ordering, signing and other nuisance, allowing you to more quickly get to the pub. 

Diving into OAuthLib (Quick Flask Twitter App) 
----------------------------------------------

**While this tutorial does not add OAuth support to a specific library it does show a fully working example of how it can be used in a typical workflow. From this it should be easy to see how it might fit in into your library of choice.**

**An OAuth server example is on its way.**

Dependencies and credentials
````````````````````````````

We will use `Flask`_, `Requests`_ and OAuthLib. The former two are available on PyPI, OAuthLib can be installed by cloning this repository and moving the oauthlib dir to site-packages.::

    #!/usr/bin/env python
    from flask import Flask, request, render_template, redirect, session
    from urlparse import parse_qs
    from oauthlib.oauth import OAuth
    import requests
    import os

    app = Flask(__name__)

.. _`Flask`: http://flask.pocoo.org/ 
.. _`Requests`: http://docs.python-requests.org/en/latest/index.html 

When registering an app with twitter you will receive a ``client key`` and a ``client secret``. You will also register a callback url which in our example is set to ``/callback``.::

    key = "<your client key>"
    secret = "<your client secret>"
    request_url = "https://api.twitter.com/oauth/request_token"
    auth_url = "http://api.twitter.com/oauth/authorize"
    access_url = "https://api.twitter.com/oauth/access_token"
    update_url = "http://api.twitter.com/1/statuses/update.json" 

Redirect based user authorization
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The first view will redirect the user in order to authorize the client access his/her twitter resources and post updates. In order to redirect the user we fetch a request token from twitter and use that to create the redirection url.::

    def demo():
        # Create an OAuth object with client key and secret set, 
        # other parameters, such as nonce, timestamp, version, will
        # be set for you automatically.
        twitter = OAuth(client_key=key,
                        client_secret=secret)

        # Create an authorization header for this particular request.
        # It will be signed using the default encryption method, HMAC-SHA1.
        header = twitter.auth_header(request_url)

        # Add it to the Authorization header
        r = requests.post(request_url, headers={"Authorization":header})

        # Extract the request token from the response
        token = parse_qs(r.text)["oauth_token"][0]

        # Create the authorization url and redirect
        auth = "{url}?oauth_token={token}".format(url=auth_url, token=token)
        return redirect(auth)

Obtaining an access token
^^^^^^^^^^^^^^^^^^^^^^^^^

Callback will receive a request token along with a verifier code. These are used to fetch an access token and secret from twitter, that we then store in a session variable. Do not show these to a user!::

    @app.route("/callback", methods=["GET", "POST"])
    def callback():
        # Fetch the access token
        verifier = request.args.get("oauth_verifier")
        token = request.args.get("oauth_token")
        twitter = OAuth(client_key=key,
                        client_secret=secret,
                        request_token=token,
                        verifier=verifier)
        header = twitter.auth_header(access_url)
        r = requests.post(access_url, headers={"Authorization" : header})

        # Extract the token, secret and screen name from the response
        info = parse_qs(r.text)
        session["access_token"] = info["oauth_token"][0]
        session["token_secret"] = info["oauth_token_secret"][0]
        session["screen_name"] = info["screen_name"][0]

        # Return the form
        return """<html><head></head><body>
        <form method="POST" action="/post">
        <input name="status_update" type="text" value="hello"/>
        <input type="submit" value="Send"/>
        </form></body></html>"""


Tweeting using the access token
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The last view uses the access token and token secret to post a status update to twitter. Note that once an access token has been obtained it can be stored but should be stored with the same precautions as passwords.::

    @app.route("/post", methods=["POST"])
    def post_update():
        post = { "status" : request.form["status_update"] }
        token_secret = session["token_secret"]
        access_token= session["access_token"]
         
        twitter = OAuth(client_key=key,
                        client_secret=secret,
                        token_secret=token_secret,
                        access_token=access_token)

        # If you send data, don't forget to pass it to auth_header
        header = twitter.auth_header(update_url, post)
        r = requests.post(update_url, data=post, headers={"Authorization": header})

        # Redirect to twitter to see the post
        return redirect("https://twitter.com/#!/%s" % session["screen_name"])

    if __name__ == "__main__":
        app.secret_key = os.urandom(24)
        app.run(debug=True)



