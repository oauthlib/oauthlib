OAuth 1 versus OAuth 2
======================

This is intended to serve as a quick guide to which OAuth version might suit
your needs best. The target audience are providers contemplating which
workflows to offer their clients but clients curious to which workflow
to use should be able to get some help too.

Before choosing it is important to understand a fundamental issue with
client - server security. **It is technically impossible to store secrets
on machines out of your control, such as a users desktop or phone.**
Without the ability to secure a secret the ability to authenticate is lost.
Because of this the provider has no way of knowing whether a request from
such a client is legitimate or from a malicious party. Great care should be
taken to restrict non authenticated clients access to resources appropriately.

**When to offer which OAuth workflow**

* Your clients reside in secure environments (i.e. able to keep secrets),
  able to use SSL/TLS and you are willing to risk unknowingly granting
  access to your users resources to a malicious third party which has
  stolen tokens (but not authentication secrets) from one of your clients.

    **(Provider)** Offer :doc:`oauth2/grants/authcode`. Impact can be limited by not
    providing refresh tokens.
    Default in :doc:`WebApplicationServer <oauth2/preconfigured_servers>`.

    **(Client)** Use :doc:`Web Application Client <oauth2/clients/webapplicationclient>`.

* Similar to above, but you are unwilling to risk malicious access based on
  stolen tokens alone.

    **(Provider)** Offer :doc:`OAuth 1 <oauth1/server>`.

    **(Client)** Use :doc:`OAuth 1 Client <oauth1/client>`.

* Your clients reside in user controlled devices with the ability to authorize
  through a web based workflow. This workflow is inherently insecure, restrict
  the privileges associated with tokens accordingly.

    **(Provider)** Offer :doc:`oauth2/grants/implicit`.
    Default in :doc:`MobileApplicationServer <oauth2/preconfigured_servers>`.

    **(Client)** Use :doc:`Mobile Application Client <oauth2/clients/mobileapplicationclient>`.

* Similar to above but without the ability to use web authorization. These
  clients must have a strong trust relationship with the users although
  they offer no additional security.

    **(Provider)** Offer non authenticated :doc:`oauth2/grants/password`.
    Default in :doc:`LegacyApplicationServer <oauth2/preconfigured_servers>`.

    **(Client)** Use :doc:`Legacy Application Client <oauth2/clients/legacyapplicationclient>`.

* Your clients are transitioning from using usernames/passwords to interact with your
  API to using OAuth tokens but for various reasons don't wish to use the web based
  authorization workflow. The clients reside in secure environments and have a strong
  trust relationship with their users.

    **(Provider)** Offer authenticated :doc:`oauth2/grants/password`.
    Default in :doc:`LegacyApplicationServer <oauth2/preconfigured_servers>`.

    **(Client)** Use :doc:`Legacy Application Client <oauth2/clients/legacyapplicationclient>`.

* You wish to run an internal, highly trusted, job acting on protected
  resources but not interacting with users.

    **(Provider)** Offer :doc:`oauth2/grants/credentials`.
    Default in :doc:`BackendApplicationServer <oauth2/preconfigured_servers>`.

    **(Client)** Use :doc:`Backend Application Client <oauth2/clients/backendapplicationclient>`.
