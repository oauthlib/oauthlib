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

RSA Signatures
--------------

OAuthLib supports the 'RSA-SHA1' signature but does not install the PyCrypto dependency by default. This is not done because PyCrypto is fairly cumbersome to install, especially on Windows. Linux and Mac OS X (?) users can install PyCrypto using pip:: 

    pip install pycrypto

Windows users will have to jump through a few hoops. The following links may be helpful:

* `Voidspace Python prebuilt binaries for PyCrypto`: http://www.voidspace.org.uk/python/modules.shtml#pycrypto

* `Can I install Python Windows packages into virtualenvs`: http://stackoverflow.com/questions/3271590/can-i-install-python-windows-packages-into-virtualenvs

* `Compiling pycrypto on Windows 7 (64bit)`: http://yorickdowne.wordpress.com/2010/12/22/compiling-pycrypto-on-win7-64/
