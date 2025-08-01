============
Contributing
============

Setup
=====

Fork on GitHub
--------------

Before you do anything else, login/signup on GitHub and fork OAuthLib from the
`GitHub project`_.

Clone your fork locally
-----------------------

If you have git-scm installed, you now clone your git repo using the following
command-line argument where <my-github-name> is your account name on GitHub::

    git clone git@github.com/<my-github-name>/oauthlib.git

Issues!
=======

The list of outstanding OAuthLib feature requests and bugs can be found on our
on our GitHub `issue tracker`_. Pick an unassigned issue that you think you can
accomplish, add a comment that you are attempting to do it, and shortly your own
personal label matching your GitHub ID will be assigned to that issue.

Feel free to propose issues that aren't described!


oauthlib community rules
========================

oauthlib is a community of developers which adheres to a very simple set of
rules.

Code of Conduct
---------------
This project adheres to a `Code of Conduct`_ based on Django. As a community
member you have to read and agree with it.

For more information please contact us and/or visit the original
`Django Code of Conduct`_ homepage.

.. _`Code of Conduct`: https://github.com/oauthlib/oauthlib/blob/master/CODE_OF_CONDUCT.md
.. _`Django Code of Conduct`: https://www.djangoproject.com/conduct/

Code of Merit
-------------
Please read the community's `Code of Merit`_. Every contributor will know the
real purpose of their contributions to this project.

.. _`Code of Merit`: http://code-of-merit.org/


Setting up topic branches and generating pull requests
======================================================

While it's handy to provide useful code snippets in an issue, it is better for
you as a developer to submit pull requests. By submitting pull request your
contribution to OAuthlib will be recorded by Github.

In git it is best to isolate each topic or feature into a "topic branch". While
individual commits allow you control over how small individual changes are made
to the code, branches are a great way to group a set of commits all related to
one feature together, or to isolate different efforts when you might be working
on multiple topics at the same time.

While it takes some experience to get the right feel about how to break up
commits, a topic branch should be limited in scope to a single ``issue`` as
submitted to an issue tracker.

Also since GitHub pegs and syncs a pull request to a specific branch, it is the
**ONLY** way that you can submit more than one fix at a time. If you submit a
pull from your master branch, you can't make any more commits to your master
without those getting added to the pull.

To create a topic branch, its easiest to use the convenient ``-b`` argument to
``git checkout``::

    git checkout -b fix-broken-thing
    Switched to a new branch 'fix-broken-thing'

You should use a verbose enough name for your branch so it is clear what it is
about.  Now you can commit your changes and regularly merge in the upstream
master as described below.

When you are ready to generate a pull request, either for preliminary review, or
for consideration of merging into the project you must first push your local
topic branch back up to GitHub::

    git push origin fix-broken-thing

Now when you go to your fork on GitHub, you will see this branch listed under
the "Source" tab where it says "Switch Branches". Go ahead and select your topic
branch from this list, and then click the "Pull request" button.

Here you can add a comment about your branch. If this in response to a submitted
issue, it is good to put a link to that issue in this initial comment. The repo
managers will be notified of your pull request and it will be reviewed (see
below for best practices). Note that you can continue to add commits to your
topic branch (and push them up to GitHub) either if you see something that needs
changing, or in response to a reviewer's comments. If a reviewer asks for
changes, you do not need to close the pull and reissue it after making changes.
Just make the changes locally, push them to GitHub, then add a comment to the
discussion section of the pull request.

Pull upstream changes into your fork
====================================

It is critical that you pull upstream changes from master into your fork on a
regular basis. Nothing is worse than putting in a days of hard work into a pull
request only to have it rejected because it has diverged too far from master.

To pull in upstream changes::

    git remote add upstream https://github.com/oauthlib/oauthlib.git
    git fetch upstream

Check the log to be sure that you actually want the changes, before merging::

    git log upstream/master

Then merge the changes that you fetched::

    git merge upstream/master

For more info, see https://help.github.com/fork-a-repo/

How to get your pull request accepted
=====================================

We want your submission. But we also want to provide a stable experience for our
users and the community. Follow these rules and you should succeed without a
problem!

Run the tests!
--------------

Before you submit a pull request, please run the entire OAuthLib test suite from
the project root via:

.. sourcecode:: bash

   $ pytest

The first thing the core committers will do is run this command. Any pull
request that fails this test suite will be **rejected**.

Testing multiple versions of Python
-----------------------------------

OAuthLib supports Python 3.8+ & PyPy 3. Testing
all versions conveniently at once can be done using `Tox`_.

.. sourcecode:: bash

   $ tox

Tox requires you to have respective python versions. We recommend using `uv`_ to install those Python versions.


.. sourcecode:: bash

   $ uv tool install tox --with tox-uv
   $ uv python list # check which versions you want to use
   $ uv python install 3.8 3.9 3.10 3.11 3.12 3.13
   $ uv python install pypy3
   $ uvx --with tox-uv tox # that run all tests with all python versions


.. _`Tox`: https://tox.readthedocs.io/en/latest/install.html
.. _`uv`: https://docs.astral.sh/uv/#python-versions

Test downstream applications
-----------------------------------

Remember, OAuthLib is used by several 3rd party projects. If you think you
submit a breaking change, confirm that other projects builds are not affected.

.. sourcecode:: bash

   $ make

Note be sure you are using ``uv`` as explained before with all python versions, including those from downstream libraries, to have all test cases running.

As of 2025, additional downstreams python versions are as below:

.. sourcecode:: bash

   $ uv python install pypy3.10


If you add code, add tests!
--------------------------------------

We've learned the hard way that code without tests is undependable. If your pull
request reduces our test coverage because it lacks tests then it will be
**rejected**.

Also, keep your tests as simple as possible. Complex tests end up requiring
their own tests. We would rather see duplicated assertions across test methods
than cunning utility methods that magically determine which assertions are
needed at a particular stage. Remember: `Explicit is better than implicit`.

Don't mix code changes with whitespace cleanup
----------------------------------------------

If you change two lines of code and correct 200 lines of whitespace issues in a
file the diff on that pull request is functionally unreadable and will be
**rejected**. Whitespace cleanups need to be in their own pull request.

Keep your pull requests limited to a single issue
--------------------------------------------------

OauthLib pull requests should be as small/atomic as possible. Large,
wide-sweeping changes in a pull request will be **rejected**, with comments to
isolate the specific code in your pull request. Some examples:

#. If you are making spelling corrections in the docs, don't modify any Python
   code.
#. If you are adding a new module don't '*cleanup*' other modules. That cleanup
   in another pull request.
#. Changing any attributes of a module, such as permissions on a file should be
   in its own pull request with explicit reasons why.

Follow PEP-8 and keep your code simple!
---------------------------------------

Memorize the Zen of Python::

    >>> python -c 'import this'

Please keep your code as clean and straightforward as possible. When we see more
than one or two functions/methods starting with `_my_special_function` or things
like `__builtins__.object = str` we start to get worried. Rather than try and
figure out your brilliant work we'll just **reject** it and send along a request
for simplification.

Furthermore, the pixel shortage is over. We want to see:

* `package` instead of `pkg`
* `grid` instead of `g`
* `my_function_that_does_things` instead of `mftdt`

Be sure to write documentation!
-------------------------------

Documentation isn't just good, it's great - and necessary with large packages
like OAuthlib. Please make sure the next person who reads your function/method
can quickly understand what it does and how. Also, please ensure the parameters
passed to each function are properly documented as well.

The project has these goals/requests for docstrings that are designed to make
the autogenerated documentation read more cleanly:

#. Every parameter in the function should be listed in the docstring, and
   should appear in the same order as they appear in the function itself.
#. If you are unsure of the best wording for a parameter description, leave it
   blank, but still include the `:param foo:` line. This will make it easier for
   maintainers to see and edit.
#. Use an existing standardized description of a parameter that appears
   elsewhere in this project's documentation whenever possible. For example,
   `request` is used as a parameter throughout the project with the description
   "OAuthlib request." - there is no reason to describe it differently in your
   function. Parameter descriptions should be a sentence that ends with a
   period - even if it is just two words.
#. When possible, include a `type` declaration for the parameter. For example,
   a "request" param is often accompanied with `:type request: oauthlib.common.Request`.
   The type is expected to be an object type reference, and should never end
   in a period.
#. If there is a textual docstring (recommended), use a single blank line to
   separate the docstring and the params.
#. When you cite class functions, please use backticks.

Consolidated example

.. code-block:: python

	def foo(self, request, client, bar=None, key=None):
		"""
                This method defines framework for `MAC Access Authentication`_ RFC.

		This method checks the `key` against the `client`. The `request` is
		passed to maintain context.

		Example MAC Authorization header, linebreaks added for clarity

		Authorization: MAC id="h480djs93hd8",
						   nonce="1336363200:dj83hs9s",
						   mac="bhCQXTVyfj5cmA9uKkPFx1zeOXM="

		:param request: OAuthlib request.
		:type request: oauthlib.common.Request
		:param client: User's defined Client object, see ``.authenticate_client``.
		:param bar: Another example.
		:param key: Another param.
		:return: Explanation of return value and type

		.. _`MAC Access Authentication`: https://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-01
		"""



How pull requests are checked, tested, and done
===============================================

First we pull the code into a local branch::

    git remote add <submitter-github-name> git@github.com:<submitter-github-name>/oauthlib.git
    git fetch <submitter-github-name>
    git checkout -b <branch-name> <submitter-github-name>/<branch-name>

Then we run the tests::

    tox

We finish with a non-fastforward merge (to preserve the branch history) and push
to GitHub::

    git checkout master
    git merge --no-ff <branch-name>
    git push upstream master

Sponsoring
==========

The OAuthlib project is open to sponsoring.

As a sponsor, you can participate by clicking on the "Sponsor" button in
the https://github.com/oauthlib/oauthlib homepage.

As a contributor, you can adhere to the sponsoring program. Feel free
to open a PR by adding your name into the ``.github/FUNDING.yml``
file.


.. _installation: install.html
.. _GitHub project: https://github.com/oauthlib/oauthlib
.. _issue tracker: https://github.com/oauthlib/oauthlib/issues
