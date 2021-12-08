Installing OAuthLib
===================


Install from PyPI
-----------------

The recommended way to install OAuthLib is from PyPI using the *pip*
program. Either just the *standard install* by itself or *with extras
for RSA*.

Standard install
^^^^^^^^^^^^^^^^

A standard installation contains the core features of OAuthLib. It can
be installed by running:

.. code-block:: bash

    pip install oauthlib

To reduce its requirements, the Python packages needed for RSA
public-key cryptography are not included in the standard installation.


With extras for RSA
^^^^^^^^^^^^^^^^^^^

To support features that use RSA public-key cryptography, PyCA's
`cryptography`_ package and the `PyJWT`_ package must also be
installed. This can be done by installing the core features of
OAuthLib along with the "signedtoken" extras.

.. code-block:: bash

    pip install 'oauthlib[signedtoken]'

Note: the quotes may be required, since shells can interpret the
square brackets as special characters.

Alternatively, those two Python packages can be installed manually by
running ``pip install cryptography`` and ``pip install pyjwt``, either
before or after installing the standard installation of OAuthLib.
PyJWT depends on cryptography, so just installing *pyjwt* should
automatically also install *cryptography*. But *cryptography* has
dependencies that can cause its installation to fail, so it can be
better to get it installed before installing PyJWT.

Install from operating system distribution
------------------------------------------

Alternatively, install it from the operating system distribution's
packaging system, if OAuthLib is available as a distribution package.
Install instructions for some distributions are shown below.

The distribution packages usually only contain the standard install of
OAuthLib. To enable support for RSA, the *cryptography* and *pyjwt*
Python packages also need to be installed: either from the
distribution packages (if available) or from PyPI.

Debian and derivatives like Ubuntu, Mint, etc.
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

    apt-get install python3-oauthlib

The Python2 package is called "python-oauthlib".

RHEL, CentOS and Fedora
^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

    yum install python3-oauthlib

The Python2 package is called "python2-oauthlib", and is available on
some distributions (e.g.Fedora 31 and CentOS 7) but not available on
others (e.g. CentOS 8).

For CentOS, the Python3 package is only available on CentOS 8 and
higher.

openSUSE
^^^^^^^^

.. code-block:: bash

    zypper in python3-oauthlib

The Python2 package is called "python-oauthlib".

Gentoo
^^^^^^

.. code-block:: bash

    emerge oauthlib

Arch
^^^^

.. code-block:: bash

    pacman -S python-oauthlib

The Python2 package is called "python2-oauthlib".

FreeBSD
^^^^^^^

.. code-block:: bash

    pkg_add -r security/py-oauthlib/


Install from GitHub
-------------------

Alternatively, install it directly from the source repository on
GitHub.  This is the "bleeding edge" version, but it may be useful for
accessing bug fixes and/or new features that have not been released.

Standard install
^^^^^^^^^^^^^^^^

The standard installation contains the core features of OAuthLib.

.. code-block:: bash

    pip install -e git+https://github.com/oauthlib/oauthlib.git#egg=oauthlib

With extras for RSA
^^^^^^^^^^^^^^^^^^^

To support features that use RSA public-key cryptography, install the
core features of OAuthLib along with the "signedtoken" extras.

.. code-block:: bash

    pip install -e 'git+https://github.com/oauthlib/oauthlib.git#egg=oauthlib[signedtoken]'

Note: the quotes may be required, since shells can interpret the
square brackets as special characters.

.. _`cryptography`: https://cryptography.io/
.. _`PyJWT`: https://pyjwt.readthedocs.io/
