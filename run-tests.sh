#!/usr/bin/env bash
# Run the tests. Note: requires bats to be installed.
set -o allexport
if [[ -z $ADFS_PASSWORD ]]; then
    read -sp 'ADFS Password: ' ADFS_PASSWORD
    printf >&2 '\n'
fi
if [[ -z $TEST_ACCOUNT ]]; then
    read -p 'AWS account name for tests: ' TEST_ACCOUNT
fi
if [[ -z $TEST_ROLE ]]; then
    read -p 'IAM role name for tests: ' TEST_ROLE
fi
TEST_ROOT=/tmp/samlkeygen-tests-$$
mkdir -p "$TEST_ROOT/bin" "$TEST_ROOT/aws"
AWS_DIR=$TEST_ROOT/aws
AWS_SHARED_CREDENTIALS_FILE=$AWS_DIR/credentials
pip install --ignore-installed --prefix="$TEST_ROOT" . awscli
PATH=$TEST_ROOT/bin:$PATH
export PYTHONPATH=$(echo "$TEST_ROOT"/lib/python*/site-packages)
if ./tests.bats; then
    # all tests succeeded
    rm -rf "$TEST_ROOT"
else
    printf 'Test results left in %s\n' "$TEST_ROOT"
fi
