Reporting bugs how-to
=====================

Bugs are reported by opening a new Github issue and you should never hesitate
to do so. Indeed, please open an issue if the documentation is unclear, you
think the API is unintuitive or if you just want some help using the library.

OAuthLib strive to have helpful exception messages and if you run into a
case where that is not true please let us know!

When reporting bugs, especially when they are hard or impossible to reproduce,
it is useful to include logging output. You can enable logging for all
oauthlib modules by adding a logger to the `oauthlib` namespace. 

.. code-block:: python

    import logging
    import sys
    log = logging.getLogger('oauthlib')
    log.addHandler(logging.StreamHandler(sys.stdout))
    log.setLevel(logging.DEBUG)

If you are using a library that builds upon OAuthLib please also enable the
logging for their modules, e.g. for `requests-oauthlib`

.. code-block:: python

    log = logging.getLogger('requests-oauthlib')
    log.addHandler(logging.StreamHandler(sys.stdout))
    log.setLevel(logging.DEBUG)

Unfortunately we can't always respond quickly to issues and to help us help you
please try and include steps to reproduce the issue. A short example can go
far, e.g. instead of

.. code-block:: python

        # oauthlib crashes when trying to sign foobar urls.

aim for

.. code-block:: python

        # OAuth 1 Clients raise a value error for the example below
        from oauthlib.oauth1 import Client
        client = Client('client-id')
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        body = 'hello world'
        client.sign('https://foo.bar', headers=headers, body=body)

An example like this immediately tells us two things

1. You might want to have the body sign but it was unclear that it needs to be
   properly encoded first.

2. You might not want the body signed but follow an example where the header was
   provided and you were not sure if you could simply skip supplying the header.

The root cause could certainly be much more complicated but in either case
steps to reproduce allow us to speculate as to what might cause the problem and
lower the number of round trips needed to find a solution.
