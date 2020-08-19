#!/usr/bin/env python
from __future__ import print_function

from ._version import __version__, __version_info__

import sys
if sys.version_info < (3, 0):
  import ConfigParser as configparser
  input = raw_input
  from urlparse import urlparse
else:
  import configparser
  from urllib.parse import urlparse

from argh import arg
from collections import namedtuple
from datetime import datetime
from fasteners.process_lock import interprocess_locked
from multiprocessing import Process
from os import path

import argh
import base64
import boto3
import botocore
import bs4
import dateutil
import getpass
import os
import re
import requests
import requests_ntlm
import shutil
import subprocess
import tempfile
import time
import xml.etree.ElementTree
import socket

# this will move if running under Docker
AWS_DIR = os.environ.get('AWS_DIR', path.expanduser('~/.aws'))
CREDS_FILE = path.join(AWS_DIR, 'credentials')
TEMP_FILE = CREDS_FILE + '.tmp'
LOCK_FILE = CREDS_FILE + '.lck'
AWS_Account_Aliases = []
AssertionExpires = 0
MaxProcesses = 20

@arg('--url',          help='URL to ADFS provider', default=os.environ.get('ADFS_URL', ''))
@arg('--region',       help='AWS region to use', default=os.environ.get('AWS_DEFAULT_REGION', 'us-east-1'))
@arg('--batch',        help='Disable all interactive prompts')
@arg('--all-accounts', help='Retrieve tokens for all accounts and roles')
@arg('--profile',      help='Naming pattern for profile names; %%a=account alias, %%r=role name (default %%a:%%r)')
@arg('--accounts',     help='Name(s) or ID(s) of AWS account(s) for which to generate tokens', nargs='+')
@arg('--role',         help='Name or ARN of role for which to generate token (default: all for account)')
@arg('--filename',     help='Name of AWS credentials file', default=CREDS_FILE)
@arg('--auto-update',  help='Continue running and update token(s) before they expire')
@arg('--domain',       help='Windows domain to authenticate to', default=os.environ.get('ADFS_DOMAIN', ''))
@arg('--username',     help='Name of user to authenticate as', default=getpass.getuser())
@arg('--password',     help='Password for user', default=os.environ.get('ADFS_PASSWORD', None))
@arg('--verbose',      help='Display trace output', default=False)
@arg('--duration',     help='Duration of token validity, in hours', default=9)
def authenticate(url=os.environ.get('ADFS_URL',''), region=os.environ.get('AWS_DEFAULT_REGION','us-east-1'),
                 batch=False, all_accounts=False, accounts=None,
                 profile='%a:%r', domain=os.environ.get('ADFS_DOMAIN',''), role=None, username=os.environ.get('USER',''),
                 password=None, filename=CREDS_FILE, auto_update=False, verbose=False, duration=9):
    "Authenticate via SAML and write out temporary security tokens to the credentials file"

    if verbose:
        trace_on()

    if not (all_accounts or accounts):
        die('Need --accounts or --all-accounts')

    if all_accounts and accounts:
        die('Specify --accounts or --all-accounts, not both.')

    # check to see if url hostname resolves to 10 network and assume VPN connection is up
    if not url:
            die('Pass ADFS URL via --url or set ADFS_URL in environment.')

    if not domain:
        die('Pass ADFS authentication domain via --domain or set ADFS_DOMAIN in environment.')

    if not username:
        if not batch:
            username = input('Username:')
        if not username:
            die('Unable to determine ADFS username. Specify via --username option or run interactively.')

    domain_username = format_domain_username(domain, username)

    if not password:
        if not batch:
            password = getpass.getpass("{}'s password: ".format(domain_username))
    if not password:
        die('No password given for {}. Respond to prompt or specify via --password option.'.format(username))

    saml_creds, saml_response = authorize(url, domain, username, password, batch)

    roles = all_roles = extract_roles(saml_response)
    if accounts:
        roles = []
    else:
        accounts = []    # set to empty list instead of None if unspecified

    # if accounts specified, look for existing profiles first
    for account in accounts:
      account_arn = None
      found_roles = []
      if account:
        try:
            account_id = int(account)
        except ValueError:
            account_id = None
        if account_id:
            account = f'arn:aws:iam::{account_id:012}'
        regex = re.compile(account)
        for principal_arn, role_arn in all_roles:
            if regex.search(principal_arn):
                account_arn = principal_arn
                break

        # no account id, look for the alias
        if not account_arn:
            if account_id:
                raise LookupError('no profile found matching account id "{:012}"'.format(account_id))
            for pair in AWS_Account_Aliases:
                if regex.search(pair['alias']):
                    arn_prefix = f'arn:aws:iam::{int(pair["id"]):012}:'
                    for principal_arn, role_arn in all_roles:
                      if principal_arn.startswith(arn_prefix):
                         account_arn = principal_arn
                         break
                    break

        # didn't find it, do it the hard way
        if not account_arn:
              for principal_arn, role_arn in all_roles:
                account_name = get_account_name(principal_arn, saml_response, role_arn, region)
                if regex.search(account_name):
                    account_arn = principal_arn
                    break

      if account_arn:
        found_roles = [r for r in all_roles if r[0] == account_arn]

      if account_arn and not found_roles:
        die('Account {} not found.'.format(account))

      roles += found_roles

    # if a role is specified, find it
    if role:
        if role.startswith('arn:'):
            roles = [r for r in roles if r[1] == role]
        else:
            regex = re.compile(role)
            roles = [r for r in roles if regex.search(r[1])]
        if not roles:
            msg = 'Role {} not found'.format(role)
            if account_arn:
                msg += ' in account {}'.format(account_arn, saml_response, role_arn, region)
            die(msg)

    # we have a list of roles to get tokens for; go do it
    validity = duration * 3600 # API wants seconds
    roles = set(roles)
    first = True
    while auto_update or first:
        try:
            shutil.copyfile(filename, TEMP_FILE)
        except IOError:
            pass
        first = False
        processes = []
        files = []
        started = time.time()
        for account_arn, role_arn in roles:

            if len(processes) >= MaxProcesses:
                 processes[0].join()
                 del processes[0]

            trace('account_arn={}, role_arn={}'.format(account_arn, role_arn));
            (fd, temp_file) = tempfile.mkstemp(text=True)
            os.close(fd)
            files.append(temp_file)
            p = Process(target=authenticate_account_role, args=(temp_file, profile, account_arn, role_arn, saml_creds, saml_response, region, validity, AssertionExpires))
            p.start()
            processes.append(p)

        for p in processes:
            p.join()

        merge_ini_files(files, TEMP_FILE)
        try:
          os.rename(TEMP_FILE, filename)
        except FileExistsError:
          if sys.version_info >= (3,3):
            os.replace(TEMP_FILE, filename)
          else:
            os.remove(filename)
            os.rename(TEMP_FILE, filename)

        for f in files:
            os.remove(f)

        if auto_update:
            trace('Token retrieval took {} seconds'.format(time.time() - started))
            next_update = time.time() + validity - 60
            while time.time() < next_update:
                counter = int((next_update - time.time()) // 60)
                print('{} minutes till credential refresh\r'.format(counter), end='')
                sys.stdout.flush()
                time.sleep(60)

def merge_ini_files(source_files, target_file):
    target = configparser.RawConfigParser()
    target.read(target_file)
    for source_file in source_files:
        source = configparser.RawConfigParser()
        source.read(source_file)
        for sect in source.sections():
            if not target.has_section(sect):
                target.add_section(sect)
            for (key, value) in source.items(sect):
                target.set(sect, key, value)

    os.makedirs(os.path.dirname(target_file), exist_ok=True)
    with open(target_file, 'wt') as f:
        target.write(f)


def samld():
    sys.argv[1:1] = ['authenticate', '--all-accounts', '--auto-update']
    main()

def awsprof():
    sys.argv[1:1] = ['select-profile']
    main()

def awsprofs():
    sys.argv[1:1] = ['list-profiles']
    main()

def awsrun():
    sys.argv[1:1] = ['run-command']
    main()

def authorize(url, domain, username, password, batch):
    ip = socket.gethostbyname( urlparse(url).hostname )
    if ip.split('.')[0] == '10':
        saml_creds, saml_response = ntlm_authenticate(url, domain, username,
                                                      password, batch)
    else:
        saml_creds, saml_response = web_authenticate(url, domain, username,
                                                     password, batch)
    return( saml_creds, saml_response)

def get_account_name(account_arn, saml_response, role_arn, region):
    "Convert account ARN to friendly name if available"
    if account_arn not in get_account_name.map:
        token = get_sts_token(role_arn, account_arn, saml_response, region)
        if token:
            get_account_name.map[account_arn] = get_account_alias(token)
    try:
        return get_account_name.map[account_arn]
    except KeyError:
        return account_arn
get_account_name.map = {}

def get_role_name(role_arn):
    "Extract role name from ARN to friendly name"
    return role_arn.split(':')[5].replace('role/', '')

def write_creds_file(filename, profile, token):
    # write a temporary file with the credentials for the given profile name
    # be left intact.
    credentials = load_credentials(filename, True)

    if not credentials.has_section(profile):
        credentials.add_section(profile)

    credentials.set(profile, 'aws_access_key_id', token['Credentials']['AccessKeyId'])
    credentials.set(profile, 'aws_secret_access_key', token['Credentials']['SecretAccessKey'])
    credentials.set(profile, 'aws_session_token', token['Credentials']['SessionToken'])
    credentials.set(profile, 'aws_security_token', token['Credentials']['SessionToken'])
    credentials.set(profile, 'last_updated', datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'))
    credentials.set(profile, 'expiration', datetime.strftime(token['Credentials']['Expiration'], '%FT%TZ'))

    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, 'wt') as credsfile:
        credentials.write(credsfile)
        credsfile.flush()
        os.fsync(credsfile)

def authenticate_account_role(filename, profile_format, principal_arn, role_arn, saml_creds, saml_response, region, validity, assertion_expires):
    global AssertionExpires
    AssertionExpires = assertion_expires
    if role_arn is None:
        die('Unable to get credentials for null role ARN')

    trace('getting token for role_arn={}, principal_arn={}'.format(role_arn,principal_arn))

    if assertion_expired():
        saml_creds, saml_response = authorize(*saml_creds, batch=True)
    token = get_sts_token(role_arn, principal_arn, saml_response, region, validity)

    if not token:
        die('Unable to get token for ({}, {})'.format(principal_arn, role_arn))
    account_name = get_account_name(principal_arn, saml_response, role_arn, region)
    role_name = get_role_name(role_arn)
    profile = profile_format.replace('%a', account_name).replace('%r', role_name)
    print('Writing credentials for profile {}'.format(profile))
    write_creds_file(filename, profile, token)

@arg('--filename',  help='Name of AWS credentials file', default=CREDS_FILE)
@arg('pattern', nargs='?', help='Restrict list to profiles matching pattern', default='.*')
def list_profiles(pattern, filename=CREDS_FILE):
    "List available AWS profiles in the credentials file"
    for (profile, conf) in sorted(load_profiles(filename, pattern)):
        print(profile)

def get_profile(filename, pattern, multi=False):
    profiles = load_profiles(filename, pattern)
    if len(profiles) == 0:
        raise LookupError('no profile found matching pattern "{}"'.format(pattern))
    elif len(profiles) > 1 and not multi:
        raise LookupError('profile pattern "{}" is ambiguous.'.format(pattern))
    if multi:
        return profiles
    else:
        return profiles[0]

def load_profiles(filename, pattern):
    config = load_credentials(filename)
    regex = re.compile(pattern)
    return [(profile, dict(config.items(profile))) for profile in config.sections() if regex.search(profile)]

def load_credentials(filename, force_refresh=False):
    if (force_refresh or not load_credentials.config or filename != load_credentials.filename):
        load_credentials.config = configparser.RawConfigParser()
        load_credentials.config.read(filename)
    return load_credentials.config
load_credentials.config = None
load_credentials.filename = None

def warn(message):
    if not '\n' in message:
        message = message + '\n'
    sys.stderr.write('{}: {}'.format('samlkeygen', message))

def die(message):
    warn(message)
    sys.exit(1)

def trace(message):
    if tracing():
        warn(message)

def trace_on():
    os.environ['SAMLAUTH_DEBUG'] = 'true'

def trace_off():
    os.environ['SAMLAUTH_DEBUG'] = 'false'

def tracing():
    return os.environ.get('SAMLAUTH_DEBUG', 'false').lower() == 'true'

def format_domain_username(domain, username):
    if '@' in username:
        return username
    elif '.' in domain:
        return f'{username}@{domain}'
    else:
        return f'{domain}\\{username}'

def extract_saml_assertion(url,response):
    global AssertionExpires
    # Now parse the ADFS Server's response to find the SAML element we need.
    #trace('response.text = "{}"'.format(response.text))
    soup = bs4.BeautifulSoup(response.text, 'html.parser')
    try:
        saml_response = [
            input_tag.get('value') for input_tag in soup.find_all('input') if input_tag.get('name') == 'SAMLResponse'
        ][-1]
    except IndexError:
        saml_response = None

    if not saml_response:
        die("Error getting SAML Response. If not on LAN, please VPN in.")

    form_action = soup.find_all('form')[0].get('action')

    if form_action:
        get_account_aliases( url, saml_response, form_action )

    AssertionExpires = int( time.time() ) + 300
    return(saml_response)

def assertion_expired():
    global AssertionExpires
    return int( time.time() ) >= AssertionExpires

def ntlm_authenticate(url, domain, username, password, batch=False, sslverification=True):

    domain_username = format_domain_username(domain, username)
    trace("into ntlm_authenticate; url={}".format(url))
    session = requests.Session()
    session.auth = requests_ntlm.HttpNtlmAuth(domain_username, password, session)
    headers = {'User-Agent': 'Mozilla/5.0 (compatible; MSIE 11; Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko'}
    response = session.get(url, verify=sslverification, headers=headers)

    saml_response = extract_saml_assertion(url,response)

    return (url, domain, username, password), saml_response

def web_authenticate(url, domain, username, password, batch=False, sslverification=True):

    session = requests.Session()
    headers = {'User-Agent': 'Mozilla/5.0 (compatible, MSIE 11, "\
                    "Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko'}
    domain_username = format_domain_username(domain, username)
    postdata= { 'UserName' : domain_username , 'Password': password, 'AuthMethod':'FormsAuthentication' }
    response = session.post( url, verify=sslverification, headers=headers, data=postdata )
    saml_response=''
    if response.reason == 'OK':
        mfa_postdata = {}
        # iterate the form extracting all hidden inputs to be passed
        soup = bs4.BeautifulSoup( response.text, "html.parser")
        for form in soup.find_all( 'form', { "id": 'passcodeForm' } ):
            for input in form.find_all( 'input' ):
                if input['type'] == 'hidden':
                    mfa_postdata[ input['name'] ] = input['value']

        mfa_postdata['Passcode'] = getpass.getpass("Pin + Rsa Token: ")

        response = session.post(url, verify=True, headers=headers, data=mfa_postdata)

        saml_response = extract_saml_assertion(url,response)
    else:
        die( "Response from {}: {}".format( urlparse(url).hostname, response.reason ) )

    return (url, domain, username, password), saml_response

def extract_roles(saml_response):
    AWS_ATTRIBUTE_ROLE = 'https://aws.amazon.com/SAML/Attributes/Role'
    ATTRIBUTE_VALUE_URN = '{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'
    role_tuple = namedtuple('RoleTuple', ['principal_arn', 'role_arn'])
    root = xml.etree.ElementTree.fromstring(base64.b64decode(saml_response))

    return [item for sublist in [
      [role_tuple(*value.text.split(',')) for value in attr.iter(ATTRIBUTE_VALUE_URN)]
        for attr in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute')
          if attr.get('Name') ==AWS_ATTRIBUTE_ROLE] for item in sublist]

def get_account_aliases(url, saml_response, form_action):
    global AWS_Account_Aliases
    session=requests.Session()
    urlparts = urlparse(url)
    headers = ({ "Host": re.sub( ':.*$', '', urlparse(form_action).netloc ),
             "Connection": 'keep-alive',
             "Content-Length": str( len( saml_response ) ),
             "Pragma": 'no-cache',
             "Cache-Control": 'no-cache',
             "Origin": urlparts.scheme + '//' + urlparts.netloc + '/',
             "Upgrade-Insecure-Requests": '1',
             "Content-Type": 'application/x-www-form-urlencoded',
             "Accept": 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
             "Referer": url,
             "Accept-Encoding": "gzip, deflate, br",
             "Accept-Language": "en-US,en;q=0.9",
             'User-Agent': 'Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko'})
    postdata= { 'SAMLResponse' :  saml_response  }
    awsr=session.post( form_action,  data=postdata, headers=headers );

    soup = bs4.BeautifulSoup( awsr.text, "html.parser")
    for divs in soup.find_all( 'div', { "class": "saml-account-name" } ):
        chunks = divs.text.split( ' ' )
        if len(chunks) > 2:
          AWS_Account_Aliases.append( { 'id':chunks[2].strip('()'), 'alias':chunks[1] } )

# Get the temporary Credentials for the passed in role, using the SAML Assertion as authentication
def get_sts_token(role_arn, principal_arn, assertion, region, validity=3600):
    # make sure the STS client request doesn't try to use our current AWS_PROFILE
    bs = botocore.session.get_session({ 'profile': ( None, ['', ''], None, None ),
                                        'config_file': (None, '', '', None) })
    bs.set_credentials('','','')
    s = boto3.session.Session(botocore_session = bs)
    client = s.client('sts', region_name = region)
    try:
        token = client.assume_role_with_saml(RoleArn = role_arn, PrincipalArn = principal_arn, SAMLAssertion = assertion, DurationSeconds = validity)
        return token
    except botocore.exceptions.ClientError as e:
        warn("Failed to get creds for {}: {}".format(role_arn, e))
        return None

def get_account_alias(token):
    global AWS_Account_Aliases
    account_id = token['AssumedRoleUser']['Arn'].split(":")[4]
    for acct in AWS_Account_Aliases:
        if acct['id'] == account_id:
            return acct['alias']

    # not found in list, probably a single-role account who didn't get the
    # role-selection form; get alias via IAM
    try:
        client = boto3.client('iam',
                              aws_access_key_id=token['Credentials']['AccessKeyId'],
                              aws_secret_access_key=token['Credentials']['SecretAccessKey'],
                              aws_session_token=token['Credentials']['SessionToken'])
        return client.list_account_aliases()['AccountAliases'][0]
    except Exception as e:
        warn("Failed to get account alias for {}".format(token['AssumedRoleUser']['Arn']))
        return token['AssumedRoleUser']['Arn'].split(":")[4] # The account Number

@arg('--filename',     help='Name of AWS credentials file', default=CREDS_FILE)
@arg('pattern', help='Run command with profile matching pattern')
def select_profile(pattern, filename=CREDS_FILE):
    "Select a unique profile name"
    profiles = [name for (name, conf) in sorted(load_profiles(filename, pattern))]
    if len(profiles) == 0:
        die('No matching profiles found.')
    if len(profiles) > 1:
        die('Pattern is not unique. It matches these profiles: \n\t' + '\n\t'.join(profiles) + '\n')
    print(profiles[0])

@arg('--all-profiles', help='Run command once each for all profiles in credentials file', default=False)
@arg('--multiple',     help='If pattern matches multiple profiles, run command in all of them', default=False)
@arg('--filename',     help='Name of AWS credentials file', default=CREDS_FILE)
@arg('--verbose',      help='Display trace output', default=False)
@arg('pattern', help='Run command with profile matching pattern')
@arg('command', help='Command to run')
def run_command(pattern, *command, **kwargs):
    "Run a command with a given profile"
    all_profiles = 'all_profiles' in kwargs and kwargs['all_profiles']
    multiple = 'multiple' in kwargs and kwargs['multiple']
    verbose = 'verbose' in kwargs and kwargs['verbose']
    filename = CREDS_FILE
    if 'filename' in kwargs:
        filename=kwargs['filename']

    if verbose:
        trace_on()
    trace('pattern={}, filename={}'.format(pattern, filename))
    profiles = [name for (name, conf) in sorted(load_profiles(filename, pattern))]
    if len(profiles) == 0:
        die('No matching profiles found.')
    if len(profiles) > 1 and not all_profiles and not multiple:
        die('Pattern is not unique. It matches these profiles: \n\t' + '\n\t'.join(profiles) + '\n')
    env = os.environ.copy()
    for profile in profiles:
       env['AWS_PROFILE'] = profile
       env['AWS_DEFAULT_PROFILE'] = profile
       subprocess.call(command, env=env)

def version():
    print(__version__)

def main():
    parser = argh.ArghParser()
    parser.prog = 'samlkeygen'
    parser.add_commands([authenticate, list_profiles, select_profile, run_command, version])
    parser.dispatch()

if __name__ == '__main__':
    main()
