Changelog
=========

0.7.2:

* (Quick fix) Unpushed locally modified files got included in the PyPI 0.7.1
  release. Doing a new clean release to address this. Please upgrade quickly
  and report any issues you are running into.

0.7.1:

* (Quick fix) Add oauthlib.common.log object back in for libraries using it.

0.7.0:

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

0.6.3: Quick fix. OAuth 1 client repr in 0.6.2 overwrote secrets when
       scrubbing for print.

0.6.2:

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

0.6.1: Draft revocation endpoint features and numerous fixes including

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

0.6.0: OAuth 1 & 2 provider API refactor with breaking changes

* All endpoint methods change contract to return 3 values instead of 4. The new
  signature is `headers`, `body`, `status code` where the initial `redirect_uri`
  has been relocated to its rightful place inside headers as `Location`.

* OAuth 1 Access Token Endpoint has a new required validator method
  `invalidate_request_token`.

* OAuth 1 Authorization Endpoint now returns a 200 response instead of 302 on
  `oob` callbacks.

0.5.1: OAuth 1 provider fix for incorrect token param in nonce validation.

0.5.0: OAuth 1 provider refactor. OAuth 2 refresh token validation fix.

0.4.2: OAuth 2 draft to RFC. Removed OAuth 2 framework decorators.

0.4.1: Documentation corrections and various small code fixes.

0.4.0: OAuth 2 Provider support (experimental).

0.3.8: OAuth 2 Client now uses custom errors and raise on expire

0.3.7: OAuth 1 optional encoding of Client.sign return values

0.3.6: Revert default urlencoding.

0.3.5: Default unicode conversion (utf-8) and urlencoding of input.

0.3.4: A number of small features and bug fixes.

0.3.3: OAuth 1 Provider verify now return useful params

0.3.2: Fixed #62, all Python 3 tests pass.

0.3.1: Python 3.1, 3.2, 3.3 support (experimental)

0.3.0: Initial OAuth 2 client support

0.2.1: Exclude non urlencoded bodies during request verification

0.2.0: OAuth provider support

0.1.4: soft dependency on PyCrypto

0.1.3: use python-rsa instead of pycrypto.

0.1.1 / 0.1.2: Fix installation of pycrypto dependency.

0.1.0: OAuth 1 client functionality seems to be working. Hooray!

0.0.x: In the beginning, there was the word.
