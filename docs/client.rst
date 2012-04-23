======
Client
======

Unicode Everywhere
------------------

OAuthLib expects you to supply all string-like parameters in unicode. If you're
using bytestrings in your library, make sure to do a proper conversion to unicode
before sending the strings to oauthlib.

Request body
------------

The OAuth 1 spec only covers signing of x-www-url-formencoded information. If
you are sending some other kind of data in the body (say, multipart file uploads),
these don't count as a body for the purposes of signing. Don't provide the body
to Client.sign() if it isn't x-www-url-formencoded data.

For convenience, you can pass body data in one of three ways:

* a dictionary
* an iterable of 2-tuples
* a properly-formated x-www-url-formencoded string
