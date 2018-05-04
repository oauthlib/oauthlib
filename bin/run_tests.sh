#!/bin/bash
set -x
set -e

DIR='package'
# Change into directory where tests are run
cd $(git rev-parse --show-toplevel)/$DIR || exit $?

if [ -z "$ENV" ] ; then
    export ENV='iso'
fi

# Run the tests
exec tox -- -s $@
