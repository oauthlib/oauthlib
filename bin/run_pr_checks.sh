#!/bin/bash

set -e -v


if [[ $# -eq 0  ]]; then


    . ~/merge_pr/_common.sh 

    log "Running PR checks [local]"


    git fetch --all

    get_pr_commit_ids
    check_for_empty_merge

    log Src Commit ID:  ${SRC_ID}
    log  Target Commit ID:  ${TARGET_ID}

    log  ----------------------------------------
    log  Merge from   : ${SRC}
    log  Merge to     : ${TARGET}
    log  ----------------------------------------

    # Check versions
    artifact_get_and_verify_version

    # Tag git repo
    check_git_tag

    get_pip

    echo -n > nosetests.xml

    docker run  \
           -v `pwd`:/app  \
           -v `pwd`/pip.conf:/root/.pip/pip.conf \
           python:3.5.3 /bin/bash /app/bin/run_pr_checks.sh run-unit


else

    case $1 in

        'run-unit')
            echo "Running PR check $1"

            pip install tox
            cd /app
            bin/run_tests.sh

            cp /app/package/nosetests.xml  /app
            chown 498 /app/nosetests.xml
            cp /app/package/coverage.xml /app
            chown 498 /app/coverage.xml
        ;;

        'upload')
            echo "Uploading to PROD"

            docker run \
                -v `pwd`:/app \
                -v $PYPI_PROD:/root/.pypirc \
                -v `pwd`/pip.conf:/root/.pip/pip.conf \
                python:3.5.3 /bin/bash /app/bin/run_pr_checks.sh upload-dkr

        ;;

        'upload-dkr')
            echo "Uploading to PROD [Inside Docker]"

            pip install tox

            cd /app/package
            tox -e upload_package prod


        ;;

        'run-integration')

            pip install tox
            cd /app
            bin/run_integration_tests.sh

        ;;

        *)
            echo "Unknown pr-check phase '$1'"
        ;;

    esac

fi
