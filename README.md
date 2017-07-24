# AWS SAML Key Gen

This is a code taken from the aws labs github account that is slightly customized to generate and put a key into ~/.aws/credentials so you can use the aws cli.

to show all options:
```
./samlapi.py help authenticate
```

example:
```
./samlapi.py authenticate --domain your_nt_domain --adurl your_ad_url -n your_nt_userid
```

example with profile and role passed:
```
./samlapi.py authenticate --domain your_nt_domain --adurl your_ad_url -n your_nt_userid --profile your_aws_profile --role your_aws_role
```
example using docker:
```
docker run -it --rm -v ~/:/root quay.io/turner/samlkeygen --domain your_nt_domain --adurl your_ad_url -n your_nt_userid
```

## Command line arguments
* -n - Required. NT ID for user
* --domain - Required. NT Domain to use
* --adurl - Required. Active Directory url
* --awsregion - Optional but defaulted to us-east-1. AWS region.
* --role - Optional. Name of role to assume.  Can be full ARN or partial role name.  (ex: aws-cloudops-sandbox-admin)
* --profile - Optional.  Name of aws profile in ~/.aws/credentials to use to store the temporary keys.  (ex: aws-cloudops-sandbox)
* --printroles - Optional.  Authenticates and prints a list of roles that the user has access to.

## Caveats

You must be vpn'd in to use this and the expiration can be a little off sometimes.
You MUST have an existing directory ~/.aws with a file named 'credentials' in it.
If you don't specify a named profile (`--profile`), you'll need to have a profile named, `"default"` in your ~/.aws/credentials file.

The script will ask you for a profile name under which to store the credentials it will generate. This may be a new stanza in the credentials file or an existing stanza to update. The update will happen without requesting a confirmation, so be careful here.
You may use a separate profile for each account if you need to switch from account to account. You may either specifiy the profile name on the command line  using '--profile <profile name>' or set the environment variable AWS_DEFAULT_PROFILE to the desired profile name.

The default region is "us-east-1".

Assumes you know python and can install the packages needed to run it. :)

At a minimum, the following packages are required and can be installed with this command (on OSX and Linux):

`sudo pip install bs4 requests_ntlm argh keyring boto `

Use `python samlapi.py authenticate -h ` to see all parameters that can be passed in

For python3

`sudo pip3 install boto3 requests bs4 requests_ntlm argh `

Use `python3 samlapi3.py authenticate -h ` to see all parameters that can be passed in


## optionally run this tool in a container (see cloud team for docker logins)

### mac/linux

add an alias to your bash profile

```
alias saml='docker run -it --rm -v ~/:/root --dns=10.189.255.249 quay.io/turner/samlkeygen'
```

then

```
$ saml -n jdoe
```

or specify a profile

```
$ saml -n jdoe --role my_aws_role -p my_profile
```

then use this profile

```
$ aws --profile my_profile ec2 describe-instances
```

### windows

```
docker run -it --rm -v $env:USERPROFILE\.aws:c:\users\containeradministrator\.aws samlkeygen.azurecr.io/saml -n jdoe --role my_role -p my_profile
```

