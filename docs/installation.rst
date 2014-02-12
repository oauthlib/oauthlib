Installing OAuthLib
===================

The recommended way to install OAuthLib is from PyPI but if you are running
into a bug or want to try out recently implemented features you will want to
try installing directly from the GitHub master branch.

For various reasons you may wish to install using your OS packaging system and
install instructions for a few are shown below. Please send a PR to add a
missing one.

Latest release on PYPI
----------------------


.. code-block:: bash

    pip install oauthlib

Bleeding edge from GitHub master
--------------------------------

.. code-block:: bash

    pip install -e git+https://github.com/idan/oauthlib.git#egg=oauthlib

Debian and derivatives like Ubuntu, Mint, etc.
---------------------------------------------

.. code-block:: bash

    apt-get install python-oauthlib
    apt-get install python3-oauthlib

Redhat and Fedora
-----------------

.. code-block:: bash

    yum install python-oauthlib
    yum install python3-oauthlib

openSUSE
--------

.. code-block:: bash

    zypper in python-oauthlib
    zypper in python3-oauthlib

Gentoo
------

.. code-block:: bash

    emerge oauthlib

Arch
----

.. code-block:: bash

    pacman -S python-oauthlib
    pacman -S python2-oauthlib

FreeBSD
-------

.. code-block:: bash

    pkg_add -r security/py-oauthlib/
