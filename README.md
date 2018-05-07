# AWS SAML Authorization Script.

This is a tool to authenticate to Amazon Web Services using the ADFS SAML provider
and create temporary tokens for use with AWS API clients.

## Two approaches

The code is packaged as a Python module; if you have a working Python
installation of a recent enough vintage, you should be able to install it
directly from PyPI (http://pypi.python.org) by running `pip install samlkeygen`.

If you regularly use Docker and would rather run the tool without installing
anything, you can run a prebuilt Docker image directly from Docker Hub
(http://dockerhub.com) with `docker run turnerlabs/samlkeygen`.

Both approaches require some environment variables and/or command-line
parameters in order to function properly; see below for details.  Of course,
you can also always clone the git repository
(https://github.com/turnerlabs/samlkeygen) and use the source directly.  Pull
requests with improvements are always welcome!

### MacOS Note
On some versions of MacOS, the stock Python install doesn't include `pip`. and
even if you install it (e.g. with `easy_install`), installing `samlkeygen` may
require upgrading some standard modules that file system security restrictions
will not permit. On such systems you will need to either take the Docker approach
or install a separate instance of Python (2.7+ or 3.x, the module works either way);
for the latter solution, consider  using Homebrew (http://brew.sh) and/or pyenv
(https://github.com/pyenv/pyenv)

## Shortcuts

When installed as a module, `samlkeygen` installs three front-end scripts
to make common use cases take less typing: `awsprof`, `awsprofs`, and `samld`. There
are bash alias definitions below to create similar commands when using the Docker
version of the tool; the github repo includes a `source`able bash script containing
those definitions.

## Configuration Parameters
The primary configuration parameters required for the authentication operation
are the URL of your ADFS service endpoint and the credentials to log into that
endpoint: your Active Directory domain, username, and password. You can provide
all of these via command-line parameters or environment variables, though for
security we recommend that you let the tool prompt you for your password (which
will not be echoed).


| Option   | Environment Variable | Description|
|----------|----------------------|------------|
|--url     | ADFS\_URL            | Complete URL to ADFS SAML endpoint for AWS
|--domain  | ADFS\_DOMAIN         | Active Directory/ADFS domain name|
|--username| USER                 | Your Active Directory username (sAMAccountName)  |
|--password| PASSWORD             | Your Active Directory password (again, we recommend you leave this unset and allow the program to prompt you for it)   |

Depending on your environment, you may also have to be on your corporate LAN or
VPN in order to authenticate. Once you have obtained keys for a profile,
though, those should work from anywhere until they expire.

### Quick start

`samlkeygen` has two basic functions: the primary one is authentication, in which
it connects to the ADFS endpoint, authenticates, and gets authorization tokens for
the user's defined SAML roles. The secondary function is to simplify the selection
of a credentials profile file for use by a command.

#### Authentication

SAML-based credentials are only good for an hour (a hard AWS-imposed limit). To
make this limit less inconvenient, `samlkeygen authenticate` provides a mode of
operation called `auto-update` which requests your password once, then runs
continually and automatically requests and saves new credentials every hour
just before the old ones expire. The supplied entry points include `samld`,
which can usually be run without arguments if the environment variables are set
properly, or with just `--username sAMAccountName` if that isn't the
same as your local `$USER` on your workstation.  Example:

```
$ samld --username gpburdell
...
Writing credentials for profile aws-shared-services:aws-shared-services-admin
Writing credentials for profile aws-shared-services:aws-shared-services-dns
Writing credentials for profile aws-ent-prod:aws-ent-prod-admin
Writing credentials for profile cdubs:aws-cdubs-admin
58 minutes till credential refresh
```

The full usage for `samlgen authenticate` may be found below.

### Profile selection

The authentication tokens will be written out to your credentials file with a
separate profile for each SAML role, named `$ACCOUNT_ALIAS:$ROLE_NAME`. You can
get a list of your profiles by running `samlkeygen list-profiles`, which
takes an optional parameter to restrict the output to those profiles matching
a substring (really a regular expression). There's an `awsprofs` alias/entry point
for this functionality:


```
$ awsprofs shared-services
aws-shared-services:aws-shared-services-admin
aws-shared-services:aws-shared-services-dns-cnn
```

These are normal AWS profiles and can be used like any other, by supplying the
`--profile` option to whatever AWS CLI command you are running,
or setting the `AWS_PROFILE` environment variable (or `AWS_DEFAULT_PROFILE` for
some older tools).  However, since the autogenerated names are somewhat long,
the script also has a subcommand that lets you select a profile via substring
or regular expression match: `select-profile` works just like `list-profiles`,
but requires that the pattern match exactly one profile. The supplied
aliases/entry points include one called `awsprof` (singular) for this use case:

```
$ awsprof shared-services
samlkeygen.py: Pattern is not unique. It matches these profiles:
        aws-shared-services:aws-shared-services-admin
        aws-shared-services:aws-shared-services-dns-cnn
```

If the pattern does match one profile, that profile's full name is output by itself;
the intent is to use the command in command-substitution:

```
$ aws --profile $(awsprof shared-services-admin) iam list-account-aliases
{
    "AccountAliases": [
        "aws-shared-services"
    ]
}
```

Finally, if you are running the local Python version, you can ask the script to
run a command for you under a given profile. The pip-installed entry poitns
include one called `awsrun` for this function; there's no corresponding Docker
alias because the Docker container would have to include the AWS command-line
tool you wanted to run this way.

That lets me replace the above example with this:

```
$ awsrun shared-services-admin aws iam list-account-aliases
{
    "AccountAliases": [
        "aws-shared-services"
    ]
}
```


## The Docker aliases

### Bash
```
alias samld='docker run -it --rm -v "${AWS_DIR:-$HOME/.aws}:/aws" -e "USER=$USER" -e "ADFS_DOMAIN=$ADFS_DOMAIN" -e "ADFS_URL=$ADFS_URL" turnerlabs/samlkeygen authenticate --all-accounts --auto-update'

alias awsprofs='docker run --rm -v ~/.aws:/aws turnerlabs/samlkeygen list-profiles'

alias awsprof='docker run --rm -v ~/.aws:/aws turnerlabs/samlkeygen select-profile'
```

### PowerShell
```
$AWS_DIR = "$env:UserProfile\.aws" -replace "\\","//"
function Run-SamlKeygenAuto {
    docker run -it --rm -v ${AWS_DIR}:/aws -e "USER=$env:UserName" `
    -e "ADFS_DOMAIN=$ADFS_DOMAIN" -e "ADFS_URL=$ADFS_URL" `
    docker run --rm -v ~/.aws:/aws turnerlabs/samlkeygen select-profile
}
New-Alias awsprof Run-SamlKeygen
```

## Full Usage documentation

```
usage: samlkeygen [-h]
                  {authenticate,list-profiles,select-profile,run-command,version}
                  ...

positional arguments:
  {authenticate,list-profiles,select-profile,run-command,version}
    authenticate        Authenticate via SAML and write out temporary security
                        tokens to the credentials file
    list-profiles       List available AWS profiles in the credentials file
    select-profile      Select a unique profile name
    run-command         Run a command with a given profile
    version

optional arguments:
  -h, --help            show this help message and exit
```

```
usage: samlkeygen authenticate [-h] [--url URL] [--region REGION] [--batch]
                               [--all-accounts] [--account ACCOUNT]
                               [--profile PROFILE] [--domain DOMAIN]
                               [--role ROLE] [--username USERNAME]
                               [--password PASSWORD] [--filename FILENAME]
                               [--auto-update] [--verbose]

Authenticate via SAML and write out temporary security tokens to the credentials file

optional arguments:
  -h, --help           show this help message and exit
  --url URL            URL to ADFS provider (default: '')
  --region REGION      AWS region to use (default: 'us-east-1')
  --batch              Disable all interactive prompts (default: False)
  --all-accounts       Retrieve tokens for all accounts and roles (default:
                       False)
  --account ACCOUNT    Name or ID of AWS account for which to generate token
                       (default: -)
  --profile PROFILE    Name to give profile in credentials file (default
                       account:role) (default: -)
  --domain DOMAIN      Windows domain to authenticate to (default: '')
  --role ROLE          Name or ARN of role for which to generate token
                       (default: all for account) (default: -)
  --username USERNAME  Name of user to authenticate as (default: 'mjreed')
  --password PASSWORD  Password for user (default: -)
  --filename FILENAME  Name of AWS credentials file (default:
                       '/Users/mjreed/.aws/credentials')
  --auto-update        Continue running and update token(s) every hour
                       (default: False)
  --verbose            Display trace output (default: False)
```

```
usage: samlkeygen list-profiles [-h] [--filename FILENAME] [pattern]

List available AWS profiles in the credentials file

positional arguments:
  pattern              Restrict list to profiles matching pattern (default:
                       '.*')

optional arguments:
  -h, --help           show this help message and exit
  --filename FILENAME  Name of AWS credentials file (default:
                       '/Users/mjreed/.aws/credentials')
```

```
usage: samlkeygen select-profile [-h] [--filename FILENAME] pattern

Select a unique profile name

positional arguments:
  pattern              Run command with profile matching pattern

optional arguments:
  -h, --help           show this help message and exit
  --filename FILENAME  Name of AWS credentials file (default:
                       '/Users/mjreed/.aws/credentials')
```
