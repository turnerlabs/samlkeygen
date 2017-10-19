#!/usr/bin/env bats
if [[ -z $ADFS_PASSWORD ]]; then
  printf >&2 'Put password in $ADFS_PASSWORD for testing.\n'
  exit 1
fi

@test "version" {
  [[ $(python -msamlkeygen version) == $(python -msamlkeygen._version) ]]
}

@test "usage 1: requires subcommand"  {
   [[ $(python -msamlkeygen 2>&1 | tail -n 1) == 'samlkeygen: error: too few arguments' ]]
}

@test "usage 2: authenticate requires account"  {
   [[ $(python -msamlkeygen authenticate 2>&1 | tail -n 1) == 'samlkeygen: Need --account or --all-accounts' ]]
}

@test "authenticate --account doesn't crash"  {
   python -msamlkeygen authenticate --account mpto --password "$ADFS_PASSWORD" >&/dev/null
}
