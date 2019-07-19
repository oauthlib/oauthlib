Changelog
=========

3.0.2 (2019-07-04)
------------------
* #650: Fixed space encoding in base string URI used in the signature base string.
* #652: Fixed OIDC /token response which wrongly returned "&state=None"
* #654: Doc: The value `state` must not be stored by the AS, only returned in /authorize response.
* #656: Fixed OIDC "nonce" checks: raise errors when it's mandatory

3.0.1 (2019-01-24)
------------------
* Fixed OAuth2.0 regression introduced in 3.0.0: Revocation with Basic auth no longer possible #644

3.0.0 (2019-01-01)
------------------
OAuth2.0 Provider - outstanding Features

* OpenID Connect Core support
* RFC7662 Introspect support
* RFC8414 OAuth2.0 Authorization Server Metadata support (#605)
* RFC7636 PKCE support (#617 #624)

OAuth2.0 Provider - API/Breaking Changes

* Add "request" to confirm_redirect_uri #504
* confirm_redirect_uri/get_default_redirect_uri has a bit changed #445
* invalid_client is now a FatalError #606
* Changed errors status code from 401 to 400:
 - invalid_grant: #264
 - invalid_scope: #620
 - access_denied/unauthorized_client/consent_required/login_required #623
 - 401 must have WWW-Authenticate HTTP Header set. #623

OAuth2.0 Provider - Bugfixes

* empty scopes no longer raise exceptions for implicit and authorization_code #475 / #406

OAuth2.0 Client - Bugfixes / Changes:

* expires_in in Implicit flow is now an integer #569
* expires is no longer overriding expires_in #506
* parse_request_uri_response is now required #499
* Unknown error=xxx raised by OAuth2 providers was not understood #431
* OAuth2's `prepare_token_request` supports sending an empty string for `client_id` (#585)
* OAuth2's `WebApplicationClient.prepare_request_body` was refactored to better
  support sending or omitting the `client_id` via a new `include_client_id` kwarg.
  By default this is included. The method will also emit a DeprecationWarning if
  a `client_id` parameter is submitted; the already configured `self.client_id`
  is the preferred option. (#585)

OAuth1.0 Client:

* Support for HMAC-SHA256 #498

General fixes:

* $ and ' are allowed to be unencoded in query strings #564
* Request attributes are no longer overriden by HTTP Headers #409
* Removed unnecessary code for handling python2.6
* Add support of python3.7 #621
* Several minors updates to setup.py and tox
* Set pytest as the default unittest framework


2.1.0 (2018-05-21)
------------------

* Fixed some copy and paste typos (#535)
* Use secrets module in Python 3.6 and later (#533)
* Add request argument to confirm_redirect_uri (#504)
* Avoid populating spurious token credentials (#542)
* Make populate attributes API public (#546)

2.0.7 (2018-03-19)
------------------

* Moved oauthlib into new organization on GitHub.
* Include license file in the generated wheel package. (#494)
* When deploying a release to PyPI, include the wheel distribution. (#496)
* Check access token in self.token dict. (#500)
* Added bottle-oauthlib to docs. (#509)
* Update repository location in Travis. (#514)
* Updated docs for organization change. (#515)
* Replace G+ with Gitter. (#517)
* Update requirements. (#518)
* Add shields for Python versions, license and RTD. (#520)
* Fix ReadTheDocs build (#521).
* Fixed "make" command to test upstream with local oauthlib. (#522)
* Replace IRC notification with Gitter Hook. (#523)
* Added Github Releases deploy provider. (#523)

2.0.6 (2017-10-20)
------------------

* 2.0.5 contains breaking changes.

2.0.5 (2017-10-19)
------------------

* Fix OAuth2Error.response_mode for #463.
* Documentation improvement.

2.0.4 (2017-09-17)
------------------
* Fixed typo that caused OAuthlib to crash because of the fix in "Address missing OIDC errors and fix a typo in the AccountSelectionRequired exception".

2.0.3 (2017-09-07)
------------------
* Address missing OIDC errors and fix a typo in the AccountSelectionRequired exception.
* Update proxy keys on CaseInsensitiveDict.update().
* Redirect errors according to OIDC's response_mode.
* Added universal wheel support.
* Added log statements to except clauses.
* According to RC7009 Section 2.1, a client should include authentication credentials when revoking its tokens.
  As discussed in #339, this is not make sense for public clients.
  However, in that case, the public client should still be checked that is infact a public client (authenticate_client_id).
* Improved prompt parameter validation.
* Added two error codes from RFC 6750.
* Hybrid response types are now be fragment-encoded.
* Added Python 3.6 to Travis CI testing and trove classifiers.
* Fixed BytesWarning issued when using a string placeholder for bytes object.
* Documented PyJWT dependency and improved logging and exception messages.
* Documentation improvements and fixes.

2.0.2 (2017-03-19)
------------------
* Dropped support for Python 2.6, 3.2 & 3.3.
* (FIX) `OpenIDConnector` will no longer raise an AttributeError when calling `openid_authorization_validator()` twice.

2.0.1 (2016-11-23)
------------------
* (FIX) Normalize handling of request.scopes list

2.0.0 (2016-09-03)
------------------
* (New Feature) **OpenID** support.
* Documentation improvements and fixes.

1.1.2 (2016-06-01)
------------------
* (Fix) Query strings should be able to include colons.
* (Fix) Cast body to a string to ensure that we can perform a regex substitution on it.

1.1.1 (2016-05-01)
------------------
* (Enhancement) Better sanitisation of Request objects __repr__.

1.1.0 (2016-04-11)
------------------
* (Fix) '(', ')', '/' and '?' are now safe characters in url encoded strings.
* (Enhancement) Added support for specifying if refresh tokens should be created on authorization code grants.
* (Fix) OAuth2Token now handles None scopes correctly.
* (Fix) Request token is now available for OAuth 1.
* (Enhancement) OAuth2Token is declared with __slots__ for smaller memory footprint.
* (Enhancement) RefreshTokenGrant now allows to set issue_new_refresh_tokens.
* Documentation improvements and fixes.

1.0.3 (2015-08-16)
------------------
* (Fix) Changed the documented return type of the ```invalidate_request_token()``` method from the RSA key to None since nobody is using the return type.
* (Enhancement) Added a validator log that will store what the endpoint has computed for debugging and logging purposes (OAuth 1 only for now).

1.0.2 (2015-08-10)
------------------
* (Fix) Allow client secret to be null for public applications that do not mandate it's specification in the query parameters.
* (Fix) Encode request body before hashing in order to prevent encoding errors in Python 3.

1.0.1 (2015-07-27)
------------------
* (Fix) Added token_type_hint to the list of default Request parameters.

1.0.0 (2015-07-19)
------------------

* (Breaking Change) Replace pycrypto with cryptography from https://cryptography.io
* (Breaking Change) Update jwt to 1.0.0 (which is backwards incompatible) no oauthlib api changes
  were made.
* (Breaking Change) Raise attribute error for non-existing attributes in the Request object.
* (Fix) Strip whitespace off of scope string.
* (Change) Don't require to return the state in the access token response.
* (Change) Hide password in logs.
* (Fix) Fix incorrect invocation of prepare_refresh_body in the OAuth2 client.
* (Fix) Handle empty/non-parsable query strings.
* (Fix) Check if an RSA key is actually needed before requiring it.
* (Change) Allow tuples for list_to_scope as well as sets and lists.
* (Change) Add code to determine if client authentication is required for OAuth2.
* (Fix) Fix error message on invalid Content-Type header for OAtuh1 signing.
* (Fix) Allow ! character in query strings.
* (Fix) OAuth1 now includes the body hash for requests that specify any content-type that isn't x-www-form-urlencoded.
* (Fix) Fixed error description in oauth1 endpoint.
* (Fix) Revocation endpoint for oauth2 will now return an empty string in the response body instead of 'None'.
* Increased test coverage.
* Performance improvements.
* Documentation improvements and fixes.

0.7.2 (2014-11-13)
------------------

* (Quick fix) Unpushed locally modified files got included in the PyPI 0.7.1
  release. Doing a new clean release to address this. Please upgrade quickly
  and report any issues you are running into.

0.7.1 (2014-10-27)
------------------

* (Quick fix) Add oauthlib.common.log object back in for libraries using it.

0.7.0 (2014-10-27)
------------------

* (Change) OAuth2 clients will not raise a Warning on scope change if
  the environment variable ``OAUTHLIB_RELAX_TOKEN_SCOPE`` is set. The token
  will now be available as an attribute on the error, ``error.token``.
  Token changes will now also be announced using blinker.
* (Fix/Feature) Automatic fixes of non-compliant OAuth2 provider responses (e.g. Facebook).
* (Fix) Logging is now tiered (per file) as opposed to logging all under ``oauthlib``.
* (Fix) Error messages should now include a description in their message.
* (Fix/Feature) Optional support for jsonp callbacks after token revocation.
* (Feature) Client side preparation of OAuth 2 token revocation requests.
* (Feature) New OAuth2 client API methods for preparing full requests.
* (Feature) OAuth1 SignatureOnlyEndpoint that only verifies signatures and client IDs.
* (Fix/Feature) Refresh token grant now allow optional refresh tokens.
* (Fix) add missing state param to OAuth2 errors.
* (Fix) add_params_to_uri now properly parse fragment.
* (Fix/Feature) All OAuth1 errors can now be imported from oauthlib.oauth1.
* (Fix/Security) OAuth2 logs will now strip client provided password, if present.
* Allow unescaped @ in urlencoded parameters.

0.6.3 (2014-06-10)
------------------

Quick fix. OAuth 1 client repr in 0.6.2 overwrote secrets when scrubbing for print.

0.6.2 (2014-06-06)
------------------

* Numerous OAuth2 provider errors now suggest a status code of 401 instead
  of 400 (#247.

* Added support for JSON web tokens with oauthlib.common.generate_signed_token.
  Install extra dependency with oauthlib[signedtoken] (#237).

* OAuth2 scopes can be arbitrary objects with __str__ defined (#240).

* OAuth 1 Clients can now register custom signature methods (#239).

* Exposed new method oauthlib.oauth2.is_secure_transport that checks whether
  the given URL is HTTPS. Checks using this method can be disabled by setting
  the environment variable OAUTHLIB_INSECURE_TRANSPORT (#249).

* OAuth1 clients now has __repr__ and will be printed with secrets scrubbed.

* OAuth1 Client.get_oauth_params now takes an oauthlib.Request as an argument.

* urldecode will now raise a much more informative error message on
  incorrectly encoded strings.

* Plenty of typo and other doc fixes.

0.6.1 (2014-01-20)
------------------

Draft revocation endpoint features and numerous fixes including:

* (OAuth 2 Provider) is_within_original_scope to check whether a refresh token
  is trying to aquire a new set of scopes that are a subset of the original scope.

* (OAuth 2 Provider) expires_in token lifetime can be set per request.

* (OAuth 2 Provider) client_authentication_required method added to differentiate
  between public and confidential clients.

* (OAuth 2 Provider) rotate_refresh_token now indicates whether a new refresh
  token should be generated during token refresh or if old should be kept.

* (OAuth 2 Provider) returned JSON headers no longer include charset.

* (OAuth 2 Provider) validate_authorizatoin_request now also includes the
  internal request object in the returned dictionary. Note that this is
  not meant to be relied upon heavily and its interface might change.

* and many style and typo fixes.

0.6.0
-----

OAuth 1 & 2 provider API refactor with breaking changes:

* All endpoint methods change contract to return 3 values instead of 4. The new
  signature is `headers`, `body`, `status code` where the initial `redirect_uri`
  has been relocated to its rightful place inside headers as `Location`.

* OAuth 1 Access Token Endpoint has a new required validator method
  `invalidate_request_token`.

* OAuth 1 Authorization Endpoint now returns a 200 response instead of 302 on
  `oob` callbacks.

0.5.1
-----

OAuth 1 provider fix for incorrect token param in nonce validation.

0.5.0
-----

OAuth 1 provider refactor. OAuth 2 refresh token validation fix.

0.4.2
-----

OAuth 2 draft to RFC. Removed OAuth 2 framework decorators.

0.4.1
-----

Documentation corrections and various small code fixes.

0.4.0
-----

OAuth 2 Provider support (experimental).

0.3.8
-----

OAuth 2 Client now uses custom errors and raise on expire.

0.3.7
-----

OAuth 1 optional encoding of Client.sign return values.

0.3.6
-----

Revert default urlencoding.

0.3.5
-----

Default unicode conversion (utf-8) and urlencoding of input.

0.3.4
-----

A number of small features and bug fixes.

0.3.3
-----

OAuth 1 Provider verify now return useful params.

0.3.2
-----

Fixed #62, all Python 3 tests pass.

0.3.1
-----

Python 3.1, 3.2, 3.3 support (experimental).

0.3.0
-----

Initial OAuth 2 client support.

0.2.1
-----

Exclude non urlencoded bodies during request verification.

0.2.0
-----

OAuth provider support.

0.1.4
-----

Soft dependency on PyCrypto.

0.1.3
-----

Use python-rsa instead of pycrypto.

0.1.1 / 0.1.2
-------------

Fix installation of pycrypto dependency.

0.1.0
-----

OAuth 1 client functionality seems to be working. Hooray!

0.0.x
-----

In the beginning, there was the word.
