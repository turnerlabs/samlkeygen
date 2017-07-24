#!/bin/bash
#
# This script allows a user to pass in an aws cli command to be executed against all SAML roles that the user has access to.
# Assumes samlapi.py is in $PATH
# Usage: samlapi_run_all_roles.sh -n "ntusername" -c "aws s3 ls"

while [[ $# -gt 1 ]]
do
key="$1"

case $key in
    -n|--ntusername)
    ntuser="$2"
    shift # past argument
    ;;
    -c|--command)
    mycommand="$2"
    shift # past argument
    ;;
    *)
            # unknown option
    ;;
esac
shift # past argument or value
done

#get list of ARNs to loop through, cut the role name instead of using the full ARN for creating profiles
arn_list=(`samlapi.py authenticate -n $ntuser --printroles | grep arn | cut -d '/' -f2`)

for i in ${arn_list[@]}; do
  samlapi.py authenticate -n $ntuser --profile $i --role $i
  sleep 1
  echo "setting AWS_DEFAULT_PROFILE to $i"
  export AWS_DEFAULT_PROFILE=$i
  echo "executing: $mycommand"
  eval $mycommand
done

unset AWS_DEFAULT_PROFILE
