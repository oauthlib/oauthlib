Release process
===============

OAuthLib has got to a point where quite a few libraries and users depend on it.
Because of this, a more careful release procedure will be introduced to make
sure all these lovely projects don't suddenly break.

When approaching a release we will run the unittests for a set of downstream
libraries using the unreleased version of OAuthLib. If OAuthLib is the cause of
failing tests we will either:

1. Find a way to introduce the change without breaking downstream. However,
   this is not always the best long term option.

2. Report the breaking change in the affected projects issue tracker or through
   Github mentions in a "master" issue on OAuthLib if many projects are
   affected.

Ideally, this process will allow rapid and graceful releases but in the case of
downstream projects remaining in a broken stage for long we will simply advice
they lock the oauthlib version in ``setup.py`` and release anyway.

Unittests might not be enough and as an extra measure we will create an
OAuthLib release issue on Github at least 2 days prior to release detailing the
changes and pings the primary contacts for each downstream project.  Please
respond within those 2 days if you have major concerns. 

How to get on the notifications list
-----------------------------------

Which projects and the instructions for testing each will be defined in
OAuthLibs ``Makefile``.  To add your project, simply open a pull request or
notify that you would like to be added by opening a github issue.
Please also include github users which can be addressed in Github mentions
as primary contacts for the project.

When is the next release?
-------------------------

Releases have been sporadic at best and I don't think that will change soon.
However, if you think it's time for a new release don't hesitate to open a 
new issue asking about it.

A note on versioning
--------------------

Historically OAuthLib has not been very good at semantic versioning but that
has changed since the 1.0.0 in 2014. Since, any major digit release
(e.g. 2.0.0) may introduce non backwards compatible changes.
Minor point (1.1.0) releases will introduce non API breaking new features and
changes. Bug releases (1.0.1) will include minor fixes that needs to be
released quickly (e.g. after a bigger release unintentionally introduced a
bug).
