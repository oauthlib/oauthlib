===========
Grant types
===========

The OpenID Connect specification adds a new `Hybrid` flow and adds
variants to the existing `Authorization Code` and `Implicit`
flows. They share the same principle: having `openid` in the scope and
a combination of new `response_type` values.


.. list-table:: OpenID Connect "response_type" Values
   :widths: 50 50
   :header-rows: 1

   * - "response_type" value
     - Flow
   * - `code`
     - Authorization Code Flow
   * - `id_token`
     - Implicit Flow
   * - `id_token token`
     - Implicit Flow
   * - `code id_token`
     - Hybrid Flow
   * - `code token`
     - Hybrid Flow
   * - `code id_token token`
     - Hybrid Flow


Special Dispatcher classes have been made to dynamically route the HTTP
requests to either an OAuth2.0 flow or an OIDC flow. It basically
checks the presence of `openid` scope in the parameters.

.. toctree::
   :maxdepth: 2

   dispatchers
   authcode
   implicit
   hybrid
   refresh_token
