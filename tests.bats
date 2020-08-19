#!/usr/bin/env bats
# Test suite for samlkeygen. Designed for bats (https://github.com/sstephenson/bats).
if [[ -z $ADFS_PASSWORD ]]; then
  printf >&2 'Put password in $ADFS_PASSWORD for testing.\n'
  exit 1
fi

@test "version" {
  [[ $(python -msamlkeygen version) == $(python -msamlkeygen._version) ]]
}

@test "usage 1: requires subcommand"  {
   [[ $(python -msamlkeygen 2>&1) == 'usage: samlkeygen '* ]]
}

@test "usage 2: authenticate requires accounts"  {
   [[ $(python -msamlkeygen authenticate 2>&1 | tail -n 1) == 'samlkeygen: Need --accounts or --all-accounts' ]]
}

@test "authenticate works when aws dir is not there yet"  {
   python -msamlkeygen authenticate --accounts "$TEST_ACCOUNT" 
}

@test "authenticate --accounts takes multiple accounts"  {
   python -msamlkeygen authenticate --accounts "$TEST_ACCOUNT" "$TEST_ACCOUNT2"
}

@test "format in --profile works"  {
   python -msamlkeygen authenticate --account "$TEST_ACCOUNT" --role "$TEST_ROLE" --profile '%r'
   grep -q "^\[$TEST_ROLE\]" "$AWS_DIR"/credentials
}

@test "awsprof entry point works"  {
   [[ $(awsprof "^$TEST_ROLE\$") == $TEST_ROLE ]]
}

@test "awsprofs entry point works"  {
   local profs
   profs=$(awsprofs "$TEST_ROLE")
   [[ $profs == $TEST_ACCOUNT:$TEST_ROLE*$TEST_ROLE ||
      $profs == $TEST_ROLE*$TEST_ACCOUNT:$TEST_ROLE ]]
}

@test "awsrun entry point works"  {
   [[ $(awsrun "^$TEST_ROLE$" aws iam list-account-aliases | jq -r '.AccountAliases[]') == "$TEST_ACCOUNT" ]]
}

@test "awsrun won't accept a pattern matching multiple profiles without --multiple"  {
   [[ $(awsrun "$TEST_ROLE" aws iam list-account-aliases 2>&1) == \
      "samlkeygen: Pattern is not unique"* ]]
}

@test "awsrun --multiple accepts a pattern matching multiple profiles"  {
  [[ "$(awsrun --multiple "$TEST_ROLE" aws iam list-account-aliases |
        jq -r -s '.[]|.AccountAliases[]')" == "$TEST_ACCOUNT"$'\n'"$TEST_ACCOUNT" ]]
}

@test "samld entry point works"  {
   local pid result tmpfile wait_time
   tmpfile=$TEST_ROOT/samld$$.out
   (samld) > "$tmpfile" 2>&1 &
   pid=$!
   wait_time=15
   if [[ -r ~/.aws/credentials ]]; then
     local count=$(grep -c '^\[' ~/.aws/credentials)
     if (( count > 25 )); then
        (( wait_time = 2 * count / 3 + 1))
     fi
   fi
   sleep $wait_time
   kill $pid
   wait $pid 2>/dev/null || true
   if [[ $(tail -n 1 "$tmpfile") == *credential*refresh* ]]; then
     rm -f "$tmpfile"
     return 0
   else
     return $?
   fi
}
